#!/usr/bin/env bash
# Configure Authentik for Beyond dev environment via the API.
# Called automatically by `just up`.
set -euo pipefail

AUTHENTIK_URL="${1:-http://localhost:9000}"

echo "configuring authentik at ${AUTHENTIK_URL}..."

# Create an API token via Django shell.
echo "  creating API token..."
TOKEN=$(docker exec beyond-authentik-server-1 ak shell -c "
from authentik.core.models import Token, TokenIntents, User
user = User.objects.get(username='akadmin')
token, created = Token.objects.get_or_create(
    identifier='beyond-setup',
    defaults={'user': user, 'intent': TokenIntents.INTENT_API, 'expiring': False}
)
print(token.key)
" 2>/dev/null | tail -1)

if [ -z "$TOKEN" ]; then
    echo "  ERROR: failed to create API token"
    exit 1
fi
echo "  got API token"

api() {
    local method="$1" path="$2" out
    shift 2
    # --fail-with-body so a rejected call says why instead of dying silently.
    if ! out=$(curl -sS --fail-with-body --connect-timeout 2 --max-time 15 -X "$method" "${AUTHENTIK_URL}${path}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${TOKEN}" \
        "$@"); then
        echo "  ERROR: ${method} ${path}: ${out}" >&2
        return 1
    fi
    printf '%s' "$out"
}

# Authentik's worker applies the default blueprints (built-in scope mappings
# AND the default provider flows) asynchronously, AFTER /-/health/ready/
# passes. Configuring before they land leaves a half-built provider behind,
# so wait for everything this script looks up first.
blueprint_objects_missing() {
    local missing="" slug
    # Tolerate API errors here too: this window is exactly when they happen.
    missing=$(api GET "/api/v3/propertymappings/provider/scope/?page_size=100" 2>/dev/null | python3 -c "
import sys, json
have = {r['scope_name'] for r in json.load(sys.stdin)['results']}
print(' '.join(sorted({'openid', 'email', 'profile', 'goauthentik.io/api'} - have)))
" 2>/dev/null) || missing="(scope mappings unreadable)"
    for slug in default-provider-authorization-implicit-consent default-provider-invalidation-flow; do
        if ! api GET "/api/v3/flows/instances/?slug=${slug}" 2>/dev/null \
            | python3 -c "import sys,json; sys.exit(0 if json.load(sys.stdin)['results'] else 1)" 2>/dev/null; then
            missing="${missing} ${slug}"
        fi
    done
    if [ -z "$(readonly_role_pk 2>/dev/null)" ]; then
        missing="${missing} authentik-Read-only-role"
    fi
    printf '%s' "${missing# }"
}

# Authentik's auto-generated read-only role (view_* on every object). The
# name filter is matched client-side because the API silently ignores
# filters it does not know.
readonly_role_pk() {
    api GET "/api/v3/rbac/roles/?name=authentik%20Read-only&page_size=100" | python3 -c "
import sys, json
print(next((r['pk'] for r in json.load(sys.stdin)['results'] if r['name'] == 'authentik Read-only'), ''))
"
}

echo "  waiting for default blueprint objects..."
for _ in $(seq 1 60); do
    MISSING=$(blueprint_objects_missing)
    [ -z "$MISSING" ] && break
    sleep 2
done
if [ -n "$MISSING" ]; then
    echo "  ERROR: default blueprint objects never appeared: ${MISSING}"
    exit 1
fi

# Get the default authorization flow (implicit consent).
echo "  finding authorization flow..."
AUTH_FLOW=$(api GET "/api/v3/flows/instances/?slug=default-provider-authorization-implicit-consent" | python3 -c "import sys,json; print(json.load(sys.stdin)['results'][0]['pk'])")
echo "  auth flow: ${AUTH_FLOW}"

# Get the default invalidation flow.
echo "  finding invalidation flow..."
INVAL_FLOW=$(api GET "/api/v3/flows/instances/?slug=default-provider-invalidation-flow" | python3 -c "import sys,json; print(json.load(sys.stdin)['results'][0]['pk'])")
echo "  invalidation flow: ${INVAL_FLOW}"

# Get the signing key.
echo "  finding signing key..."
SIGNING_KEY=$(api GET "/api/v3/crypto/certificatekeypairs/?name=authentik+Self-signed+Certificate" | python3 -c "import sys,json; r=json.load(sys.stdin)['results']; print(r[0]['pk'] if r else '')")
if [ -z "$SIGNING_KEY" ]; then
    SIGNING_KEY_JSON="null"
else
    echo "  key: ${SIGNING_KEY}"
    SIGNING_KEY_JSON="\"${SIGNING_KEY}\""
fi

# Get scope mapping PKs.
echo "  finding scope mappings..."
# Filter client-side: the API silently ignores `scope_name__in` and returns
# every mapping, which put goauthentik.io/api on the login client.
SCOPE_MAPPINGS=$(api GET "/api/v3/propertymappings/provider/scope/?page_size=100" | python3 -c "
import sys, json
results = json.load(sys.stdin)['results']
pks = [r['pk'] for r in results if r['scope_name'] in ('openid', 'email', 'profile')]
print(json.dumps(pks))
")
echo "  scopes: ${SCOPE_MAPPINGS}"

# Create a custom 'groups' scope mapping if it doesn't exist.
echo "  checking groups scope mapping..."
GROUPS_MAPPING=$(api GET "/api/v3/propertymappings/provider/scope/?scope_name=groups" | python3 -c "import sys,json; r=json.load(sys.stdin)['results']; print(r[0]['pk'] if r else '')")
if [ -z "$GROUPS_MAPPING" ]; then
    echo "  creating groups scope mapping..."
    GROUPS_MAPPING=$(api POST "/api/v3/propertymappings/provider/scope/" -d '{
        "name": "beyond: groups",
        "scope_name": "groups",
        "expression": "return {\"groups\": [group.name for group in request.user.ak_groups.all()]}"
    }' | python3 -c "import sys,json; print(json.load(sys.stdin)['pk'])")
    echo "  groups mapping pk: ${GROUPS_MAPPING}"
fi

# Add the groups mapping to the scope list.
SCOPE_MAPPINGS=$(echo "$SCOPE_MAPPINGS" | python3 -c "
import sys, json
pks = json.load(sys.stdin)
pks.append('${GROUPS_MAPPING}')
print(json.dumps(pks))
")

# Provider payload (shared between create and update).
PROVIDER_BODY="{
    \"name\": \"beyond-dev\",
    \"authorization_flow\": \"${AUTH_FLOW}\",
    \"invalidation_flow\": \"${INVAL_FLOW}\",
    \"client_type\": \"confidential\",
    \"client_id\": \"beyond-dev-client-id\",
    \"client_secret\": \"beyond-dev-client-secret\",
    \"grant_types\": [\"authorization_code\", \"refresh_token\"],
    \"redirect_uris\": [
        {\"matching_mode\": \"strict\", \"url\": \"https://localhost:8443/oidc/callback\"},
        {\"matching_mode\": \"strict\", \"url\": \"https://echo.localhost:8443/oidc/callback\"},
        {\"matching_mode\": \"regex\", \"url\": \"http://127\\\\.0\\\\.0\\\\.1:\\\\d+/oidc/callback\"},
        {\"matching_mode\": \"regex\", \"url\": \"https://127\\\\.0\\\\.0\\\\.1:\\\\d+/oidc/callback\"}
    ],
    \"signing_key\": ${SIGNING_KEY_JSON},
    \"property_mappings\": ${SCOPE_MAPPINGS},
    \"sub_mode\": \"hashed_user_id\",
    \"include_claims_in_id_token\": true
}"

# Create or update OAuth2 provider.
EXISTING=$(api GET "/api/v3/providers/oauth2/?name=beyond-dev" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['results']))")
if [ "$EXISTING" != "0" ]; then
    PROVIDER_PK=$(api GET "/api/v3/providers/oauth2/?name=beyond-dev" | python3 -c "import sys,json; print(json.load(sys.stdin)['results'][0]['pk'])")
    echo "  updating existing provider (pk: ${PROVIDER_PK})..."
    api PUT "/api/v3/providers/oauth2/${PROVIDER_PK}/" -d "$PROVIDER_BODY" > /dev/null
else
    echo "  creating OAuth2 provider..."
    PROVIDER_PK=$(api POST "/api/v3/providers/oauth2/" -d "$PROVIDER_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['pk'])")
    echo "  provider pk: ${PROVIDER_PK}"
fi

# Create or update application. The update path keeps meta_launch_url and the
# provider link current for dev stacks that were set up before those values
# changed (e.g. the http -> https launch URL migration).
EXISTING_APP_JSON=$(api GET "/api/v3/core/applications/?slug=beyond-dev")
EXISTING_APP=$(echo "$EXISTING_APP_JSON" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['results']))")
if [ "$EXISTING_APP" != "0" ]; then
    # The applications endpoint is keyed by slug, not pk (pk 404s).
    echo "  updating existing application (slug: beyond-dev)..."
    api PATCH "/api/v3/core/applications/beyond-dev/" -d "{
        \"provider\": ${PROVIDER_PK},
        \"meta_launch_url\": \"https://localhost:8443\"
    }" > /dev/null
    echo "  application updated"
else
    echo "  creating application..."
    api POST "/api/v3/core/applications/" -d "{
        \"name\": \"Beyond (dev)\",
        \"slug\": \"beyond-dev\",
        \"provider\": ${PROVIDER_PK},
        \"meta_launch_url\": \"https://localhost:8443\"
    }" > /dev/null
    echo "  application created"
fi

# --- Mint OAuth client (app-password mint page) ---
# A dedicated PUBLIC client (PKCE, no secret) carrying the goauthentik.io/api
# scope so its code-exchange access token is an Authentik API bearer for the
# user. Separate from beyond-dev so the API scope never rides the login client.
echo "  finding goauthentik.io/api scope mapping..."
API_SCOPE=$(api GET "/api/v3/propertymappings/provider/scope/?scope_name=goauthentik.io%2Fapi" | python3 -c "import sys,json; r=json.load(sys.stdin)['results']; print(r[0]['pk'] if r else '')")
if [ -z "$API_SCOPE" ]; then
    echo "  ERROR: goauthentik.io/api scope mapping not found"
    exit 1
fi
# Mint scopes = the beyond-dev set (openid/email/profile/groups) + the API scope.
MINT_SCOPE_MAPPINGS=$(echo "$SCOPE_MAPPINGS" | python3 -c "
import sys, json
pks = json.load(sys.stdin)
pks.append('${API_SCOPE}')
print(json.dumps(pks))
")

MINT_PROVIDER_BODY="{
    \"name\": \"beyond-mint-dev\",
    \"authorization_flow\": \"${AUTH_FLOW}\",
    \"invalidation_flow\": \"${INVAL_FLOW}\",
    \"client_type\": \"public\",
    \"client_id\": \"beyond-mint-dev-client-id\",
    \"grant_types\": [\"authorization_code\", \"client_credentials\", \"refresh_token\"],
    \"redirect_uris\": [
        {\"matching_mode\": \"regex\", \"url\": \"http://127\\\\.0\\\\.0\\\\.1:\\\\d+/mint/callback\"},
        {\"matching_mode\": \"regex\", \"url\": \"https://127\\\\.0\\\\.0\\\\.1:\\\\d+/mint/callback\"}
    ],
    \"signing_key\": ${SIGNING_KEY_JSON},
    \"property_mappings\": ${MINT_SCOPE_MAPPINGS},
    \"sub_mode\": \"hashed_user_id\",
    \"include_claims_in_id_token\": true
}"

EXISTING_MINT=$(api GET "/api/v3/providers/oauth2/?name=beyond-mint-dev" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['results']))")
if [ "$EXISTING_MINT" != "0" ]; then
    MINT_PROVIDER_PK=$(api GET "/api/v3/providers/oauth2/?name=beyond-mint-dev" | python3 -c "import sys,json; print(json.load(sys.stdin)['results'][0]['pk'])")
    echo "  updating existing mint provider (pk: ${MINT_PROVIDER_PK})..."
    api PUT "/api/v3/providers/oauth2/${MINT_PROVIDER_PK}/" -d "$MINT_PROVIDER_BODY" > /dev/null
else
    echo "  creating mint OAuth2 provider..."
    MINT_PROVIDER_PK=$(api POST "/api/v3/providers/oauth2/" -d "$MINT_PROVIDER_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['pk'])")
    echo "  mint provider pk: ${MINT_PROVIDER_PK}"
fi

EXISTING_MINT_APP=$(api GET "/api/v3/core/applications/?slug=beyond-mint-dev" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['results']))")
if [ "$EXISTING_MINT_APP" != "0" ]; then
    echo "  mint application already exists"
else
    echo "  creating mint application..."
    api POST "/api/v3/core/applications/" -d "{
        \"name\": \"Beyond Mint (dev)\",
        \"slug\": \"beyond-mint-dev\",
        \"provider\": ${MINT_PROVIDER_PK}
    }" > /dev/null
    echo "  mint application created"
fi

# Create groups.
for group_name in engineering platform; do
    EXISTING_GRP=$(api GET "/api/v3/core/groups/?name=${group_name}" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['results']))")
    if [ "$EXISTING_GRP" = "0" ]; then
        echo "  creating ${group_name} group..."
        api POST "/api/v3/core/groups/" -d "{\"name\":\"${group_name}\"}" > /dev/null
    fi
done
ENG_GRP_PK=$(api GET "/api/v3/core/groups/?name=engineering" | python3 -c "import sys,json; print(json.load(sys.stdin)['results'][0]['pk'])")

# Create test user. Username IS the email, matching prod (Google enrollment
# produces email-shaped usernames). This matters: Authentik's
# client-credentials grant validates the app-password `username` against the
# user's username field, and beyond renders the mint composite as
# <email>:<key> — so username must equal email for a minted key to validate
# through credential_auth. A username of "test" here would silently make dev
# minted keys unvalidatable, unlike prod.
EXISTING_USER=$(api GET "/api/v3/core/users/?username=test@beyond.local" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['results']))")
if [ "$EXISTING_USER" = "0" ]; then
    echo "  creating test user..."
    # token-maximum-lifetime lets this user mint app passwords with the 365d
    # expiry the mint page requests; without it Authentik caps at the tenant
    # default (1 day) and the mint page's cap-exceeded path fires.
    USER_PK=$(api POST "/api/v3/core/users/" -d "{
        \"username\": \"test@beyond.local\",
        \"name\": \"Test User\",
        \"email\": \"test@beyond.local\",
        \"is_active\": true,
        \"groups\": [\"${ENG_GRP_PK}\"],
        \"attributes\": {\"goauthentik.io/user/token-maximum-lifetime\": \"days=365\"}
    }" | python3 -c "import sys,json; print(json.load(sys.stdin)['pk'])")
    api POST "/api/v3/core/users/${USER_PK}/set_password/" -d '{"password":"test"}' > /dev/null
    echo "  test user created (test@beyond.local / test)"
else
    echo "  test user already exists"
fi
PLATFORM_GRP_PK=$(api GET "/api/v3/core/groups/?name=platform" | python3 -c "import sys,json; print(json.load(sys.stdin)['results'][0]['pk'])")

# --- Beyond's Authentik API identity ---
# Mirrors prod: a non-superuser service account whose only permissions come
# from Authentik's auto-generated "authentik Read-only" role, granted through
# a group. Beyond uses it for user validation and to read application policy
# bindings. The token key is fixed so .env can carry it; development only.
DEV_API_USER="beyond-dev-api-reader"
DEV_API_TOKEN="beyond-dev-api-reader-token"
echo "  configuring read-only API service account..."
READONLY_ROLE_PK=$(readonly_role_pk)
API_USER_PK=$(api GET "/api/v3/core/users/?username=${DEV_API_USER}" | python3 -c "import sys,json; r=json.load(sys.stdin)['results']; print(r[0]['pk'] if r else '')")
if [ -z "$API_USER_PK" ]; then
    API_USER_PK=$(api POST "/api/v3/core/users/" -d "{
        \"username\": \"${DEV_API_USER}\",
        \"name\": \"Beyond API reader (dev)\",
        \"type\": \"service_account\",
        \"path\": \"goauthentik.io/service-accounts\",
        \"is_active\": true
    }" | python3 -c "import sys,json; print(json.load(sys.stdin)['pk'])")
fi
READERS_GRP_PK=$(api GET "/api/v3/core/groups/?name=beyond-dev-api-readers" | python3 -c "import sys,json; r=json.load(sys.stdin)['results']; print(r[0]['pk'] if r else '')")
READERS_BODY="{\"name\":\"beyond-dev-api-readers\",\"roles\":[\"${READONLY_ROLE_PK}\"],\"users\":[${API_USER_PK}]}"
if [ -z "$READERS_GRP_PK" ]; then
    api POST "/api/v3/core/groups/" -d "$READERS_BODY" > /dev/null
else
    api PATCH "/api/v3/core/groups/${READERS_GRP_PK}/" -d "$READERS_BODY" > /dev/null
fi
if ! api GET "/api/v3/core/tokens/${DEV_API_USER}/" > /dev/null 2>&1; then
    api POST "/api/v3/core/tokens/" -d "{
        \"identifier\": \"${DEV_API_USER}\",
        \"intent\": \"api\",
        \"user\": ${API_USER_PK},
        \"expiring\": false
    }" > /dev/null
fi
api POST "/api/v3/core/tokens/${DEV_API_USER}/set_key/" -d "{\"key\":\"${DEV_API_TOKEN}\"}" > /dev/null

# --- Application policy fixtures ---
# A Beyond route named like an Authentik application takes that application's
# group bindings as its only access list. `echo` (the dev route) is bound to
# engineering; beyond-e2e-platform is bound to platform for the e2e tests.
# Look applications up by slug: the list endpoint only returns applications
# the caller may access, which hides group-bound ones from akadmin.
ensure_bound_app() {
    local slug="$1" name="$2" group_pk="$3" app_pk
    if ! app_pk=$(api GET "/api/v3/core/applications/${slug}/" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['pk'])" 2>/dev/null); then
        echo "  creating ${slug} application..."
        app_pk=$(api POST "/api/v3/core/applications/" -d "{\"name\":\"${name}\",\"slug\":\"${slug}\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['pk'])")
    fi
    if ! api GET "/api/v3/policies/bindings/?target=${app_pk}&page_size=100" | python3 -c "
import sys, json
sys.exit(0 if any(b['target'] == '${app_pk}' and b['group'] == '${group_pk}' for b in json.load(sys.stdin)['results']) else 1)
"; then
        api POST "/api/v3/policies/bindings/" -d "{
            \"target\": \"${app_pk}\",
            \"group\": \"${group_pk}\",
            \"order\": 0,
            \"enabled\": true,
            \"negate\": false,
            \"timeout\": 30
        }" > /dev/null
    fi
}
ensure_bound_app echo "Echo (dev)" "$ENG_GRP_PK"
ensure_bound_app beyond-e2e-platform "Beyond e2e: platform only" "$PLATFORM_GRP_PK"

# Verify OIDC is working.
echo ""
echo "  verifying OIDC discovery..."
ISSUER=$(curl -sf --connect-timeout 2 --max-time 15 "${AUTHENTIK_URL}/application/o/beyond-dev/.well-known/openid-configuration" | python3 -c "import sys,json; print(json.load(sys.stdin).get('issuer','FAILED'))" 2>/dev/null || echo "FAILED")
if [ "$ISSUER" = "FAILED" ]; then
    echo "  WARNING: OIDC discovery not yet available (may need a moment)"
else
    echo "  OIDC issuer: ${ISSUER}"
fi

echo ""
echo "authentik configured!"
echo "  OIDC discovery: ${AUTHENTIK_URL}/application/o/beyond-dev/.well-known/openid-configuration"
echo "  client_id:      beyond-dev-client-id"
echo "  client_secret:  beyond-dev-client-secret"
echo "  test user:      test@beyond.local / test (in 'engineering' group)"
echo "  API token:      ${DEV_API_TOKEN} (read-only service account ${DEV_API_USER})"
