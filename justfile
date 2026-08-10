set shell := ["bash", "-cu"]
set dotenv-load
set dotenv-required

# Lints and runs all tests
default: lint test

# Ensures that all tools required for local development are installed
install-tools:
    go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.10.1
    go install gotest.tools/gotestsum@v1.13.0

# Stands up local development dependencies in docker
up:
    #!/usr/bin/env bash
    set -euo pipefail

    wait_for_url() {
        local name="$1"
        local url="$2"
        local timeout_seconds="$3"
        local deadline=$((SECONDS + timeout_seconds))

        echo "waiting for ${name}..."
        until curl -fsS --connect-timeout 2 --max-time 5 "${url}" >/dev/null; do
            if (( SECONDS >= deadline )); then
                echo "ERROR: timed out waiting for ${name} at ${url}" >&2
                echo "" >&2
                docker compose ps >&2
                echo "" >&2
                docker compose logs --no-color --tail=80 authentik-server >&2
                return 1
            fi
            sleep 2
        done
        echo "${name} is ready"
    }

    docker compose up -d --remove-orphans --build --wait --wait-timeout 180

    wait_for_url "authentik" "http://localhost:9000/-/health/ready/" 120

    # Configure authentik OIDC provider for beyond (retry on failure since
    # Authentik may still be running initial migrations after health check passes).
    setup_ok=false
    for i in 1 2 3; do
        if bash dev/beyond/authentik/setup.sh; then
            setup_ok=true
            break
        fi
        if [ "$i" != "3" ]; then
            echo "  setup attempt $i failed, retrying in 5s..."
            sleep 5
        else
            echo "  setup attempt $i failed"
        fi
    done
    if [ "${setup_ok}" != "true" ]; then
        echo "ERROR: failed to configure authentik after 3 attempts" >&2
        exit 1
    fi

    echo -e "\ndevelopment environment is ready"

# Tears down the local development dependencies
down:
    docker compose down --remove-orphans --volumes

# Opens a psql shell (usage: just psql [dbname] [args...])
psql DB="beyond" *ARGS="":
    docker exec -it beyond-postgres-1 psql -U beyond {{DB}} {{ARGS}}

# Lints the code
lint:
    golangci-lint run --timeout 5m ./...

# Builds all binaries to ./bin/
build:
    mkdir -p bin
    go build -o bin/ ./cmd/...

# Builds and installs all binaries
install:
    go install ./cmd/...

# Builds and runs a go executable
run CMD *ARGS:
    go run ./cmd/{{CMD}} {{ARGS}}

# Runs the tests
test *ARGS="./...":
    gotestsum --format-hide-empty-pkg --format-icons hivis -- -count=1 {{ARGS}}

# Runs the tests with the race detector enabled
test-race *ARGS="./...":
    just test -race {{ARGS}}

# Runs benchmarks
bench *ARGS="./...":
    go test -bench=. -benchmem -count=1 -run='^$' {{ARGS}}
