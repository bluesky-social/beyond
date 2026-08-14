package beyond

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Beyond Prometheus metrics. We prefer histograms over standalone counters —
// request counts and error rates can be derived from histogram _count.

var (
	// --- HTTP Proxy ---

	// httpRequestDuration tracks the full lifecycle of public HTTP requests,
	// including proxied applications and Beyond's authenticated portal.
	// Labels: method, decision (allow/deny/upgrade/error/redirect), status_code,
	// host. "redirect" is a browser sent into the OIDC login flow.
	//
	// Deliberately NO email label: it is unbounded user-PII cardinality (every
	// distinct user mints a fresh time series × buckets × other labels) and
	// lands PII in Prometheus/federation/Grafana retention. Per-user breakdown
	// belongs in access_logs (bounded Postgres rows), not in metric labels.
	// host and method are clamped to config/verb sets for the same
	// cardinality-containment reason.
	httpRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "beyond",
		Name:      "http_request_duration_seconds",
		Help:      "Duration of public HTTP requests.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"method", "decision", "status_code", "host"})

	// credentialValidations counts credential_auth validation outcomes.
	// Labels: outcome (ok/invalid/unavailable) — "invalid" is a rejected
	// credential (bad user/key, policy-denied, missing claims), "unavailable"
	// is a fail-closed on Authentik being unreachable/erroring. No host label:
	// this mode has a single app (the AI gateway) and per-host breakdown lives
	// in access_logs. A standalone counter (not a histogram) because the
	// outcome mix, not the latency, is what alerting cares about here; request
	// latency is already covered by httpRequestDuration via the logHTTP closure.
	credentialValidations = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "beyond",
		Name:      "credential_validations_total",
		Help:      "Total credential_auth validations by outcome.",
	}, []string{"outcome"})

	// mintOperations counts app-password mint outcomes. Labels: outcome —
	//   minted        a token was created and its composite rendered
	//   group_denied  the id_token groups failed allowed_groups (no write sent)
	//   csrf_rejected POST /start-mint without a valid CSRF token
	//   replay        a callback with a consumed/absent state cookie (no write)
	//   cap_exceeded  Authentik rejected the requested expiry (> the user's cap)
	//   unavailable   Authentik unreachable / 5xx / timeout during the API calls
	//   error         any other failure (bad callback, exchange failure, etc.)
	//   orphan        token-create succeeded but view_key/render failed
	// No host label: a single mint app exists and per-host breakdown lives in
	// access_logs. A standalone counter (outcome mix, not latency, is what
	// alerting cares about) — same rationale as credentialValidations.
	mintOperations = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "beyond",
		Name:      "mint_operations_total",
		Help:      "Total app-password mint operations by outcome.",
	}, []string{"outcome"})

	// --- User Validation ---

	// userValidationDuration tracks time to check user status.
	// Labels: source (cache/api), result (active/inactive).
	userValidationDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "beyond",
		Name:      "user_validation_duration_seconds",
		Help:      "Duration of user validation checks against the identity provider.",
		Buckets:   []float64{0.0001, 0.001, 0.01, 0.05, 0.1, 0.5, 1, 5},
	}, []string{"source", "result"})

	// --- OIDC ---

	// oidcCallbackDuration tracks OIDC callback processing time.
	// Labels: status (success/error).
	oidcCallbackDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "beyond",
		Name:      "oidc_callback_duration_seconds",
		Help:      "Duration of OIDC callback processing.",
		Buckets:   []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5},
	}, []string{"status"})

	// --- Access Log DB ---

	// accessLogFlushDuration tracks batch write time to the database.
	accessLogFlushDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "beyond",
		Name:      "access_log_flush_duration_seconds",
		Help:      "Duration of access log batch writes to the database.",
		Buckets:   []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
	})

	// accessLogFlushSize tracks the number of entries per batch flush.
	accessLogFlushSize = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "beyond",
		Name:      "access_log_flush_entries",
		Help:      "Number of entries per access log batch flush.",
		Buckets:   []float64{1, 5, 10, 25, 50, 100},
	})

	// accessLogDroppedEntries counts audit-log entries permanently lost
	// because the in-memory retry buffer overflowed (DB unreachable long
	// enough to exceed maxBufferedEntries). This is the alertable signal that
	// the access trail — beyond's primary access-logging mechanism — has gaps.
	accessLogDroppedEntries = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "beyond",
		Name:      "access_log_dropped_entries_total",
		Help:      "Total access log entries dropped because the retry buffer overflowed.",
	})
)
