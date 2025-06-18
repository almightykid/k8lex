package clusterpolicyvalidator

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// Policy evaluation metrics
	validationAttempts = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_validation_total",
			Help: "Total number of resources validation attempts by the ClusterPolicyValidator.",
		},
	)

	policyEvaluationTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_policy_evaluation_total",
			Help: "Total number of policy evaluations.",
		},
		[]string{"policy_name", "resource_kind"},
	)

	policyViolations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_violations_total",
			Help: "Total number of policy violations detected by the ClusterPolicyValidator.",
		},
		[]string{"policy_name", "resource_kind", "severity", "action"},
	)

	// Action metrics
	actionTakenTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_action_taken_total",
			Help: "Total number of actions taken by the ClusterPolicyValidator.",
		},
		[]string{"action", "resource_kind", "severity"},
	)

	// Policy bypass metrics
	policyBypassTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_policy_bypass_total",
			Help: "Total number of policy bypasses by type.",
		},
		[]string{"bypass_type", "resource_kind"},
	)

	// Performance metrics
	reconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "clusterpolicyvalidator_reconcile_duration_seconds",
			Help:    "Histogram of reconcile durations for ClusterPolicyValidator.",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120},
		},
		[]string{"controller", "result"},
	)

	policyEvaluationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "clusterpolicyvalidator_policy_evaluation_duration_seconds",
			Help:    "Histogram of policy evaluation durations.",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		},
		[]string{"policy_name", "resource_kind"},
	)

	evaluationLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "clusterpolicyvalidator_evaluation_latency_seconds",
			Help:    "Histogram of policy evaluation latencies.",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		},
		[]string{"evaluation_type", "resource_kind"},
	)

	// Cache metrics
	cacheSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clusterpolicyvalidator_cache_size",
			Help: "Current size of various caches.",
		},
		[]string{"cache_type"},
	)

	// JQ cache metrics
	jqCacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_jq_cache_hits_total",
			Help: "Total number of JQ cache hits.",
		},
	)

	jqCacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_jq_cache_misses_total",
			Help: "Total number of JQ cache misses.",
		},
	)

	cacheHitRatio = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clusterpolicyvalidator_cache_hit_ratio",
			Help: "Cache hit ratio for various caches.",
		},
		[]string{"cache_type"},
	)

	// Circuit breaker metrics
	circuitBreakerState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clusterpolicyvalidator_circuit_breaker_state",
			Help: "Current state of circuit breakers (0=closed, 1=open, 2=half-open).",
		},
		[]string{"state"},
	)

	circuitBreakerFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_circuit_breaker_failures_total",
			Help: "Total number of failures that triggered circuit breaker state changes.",
		},
		[]string{"breaker_type"},
	)

	// Resource processing metrics
	resourceProcessedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_resource_processed_total",
			Help: "Total number of resources successfully processed by the ClusterPolicyValidator reconciler.",
		},
		[]string{"resource_kind"},
	)

	// Error metrics
	errorTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_error_total",
			Help: "Total number of errors encountered during ClusterPolicyValidator operations.",
		},
		[]string{"error_type", "resource_kind", "severity"},
	)

	// Retry metrics
	retryAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_retry_attempts_total",
			Help: "Total number of retry attempts for failed operations.",
		},
		[]string{"operation", "attempt", "result"},
	)

	// Concurrency metrics
	concurrentEvaluations = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "clusterpolicyvalidator_concurrent_evaluations",
			Help: "Current number of concurrent policy evaluations.",
		},
	)

	// Policy configuration metrics
	policyCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "clusterpolicyvalidator_policy_count",
			Help: "Total number of active policies.",
		},
	)

	// Policy conflict metrics
	policyConflicts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_policy_conflicts_total",
			Help: "Total number of policy conflicts.",
		},
		[]string{"resolution_strategy", "resource_path"},
	)

	// Namespace filtering metrics
	namespaceFilteredEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_namespace_filtered_events_total",
			Help: "Total number of namespace filtering events.",
		},
		[]string{"namespace", "action", "reason"},
	)

	policyRuleCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clusterpolicyvalidator_policy_rule_count",
			Help: "Number of rules per policy.",
		},
		[]string{"policy_name"},
	)

	// failureMode tracks the current failure mode of the controller
	failureMode = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clusterpolicyvalidator_failure_mode",
			Help: "Current failure mode of the controller (fail-secure or fail-safe)",
		},
		[]string{"mode"},
	)
)

func init() {
	// Register all metrics
	metrics.Registry.MustRegister(
		validationAttempts,
		policyEvaluationTotal,
		policyViolations,
		actionTakenTotal,
		policyBypassTotal,
		reconcileDuration,
		policyEvaluationDuration,
		evaluationLatency,
		cacheSize,
		jqCacheHits,
		jqCacheMisses,
		cacheHitRatio,
		circuitBreakerState,
		circuitBreakerFailures,
		resourceProcessedTotal,
		errorTotal,
		retryAttempts,
		concurrentEvaluations,
		policyCount,
		policyRuleCount,
		failureMode,
		namespaceFilteredEvents,
		policyConflicts,
	)
}

// updateCacheMetrics updates cache-related metrics
func updateCacheMetrics(cacheType string, size int, hits, misses int64) {
	cacheSize.WithLabelValues(cacheType).Set(float64(size))
	if hits+misses > 0 {
		ratio := float64(hits) / float64(hits+misses)
		cacheHitRatio.WithLabelValues(cacheType).Set(ratio)
	}
}

// recordPolicyMetrics records metrics for policy evaluation
func recordPolicyMetrics(policyName, resourceKind string, duration time.Duration, violations int) {
	policyEvaluationDuration.WithLabelValues(policyName, resourceKind).Observe(duration.Seconds())
	if violations > 0 {
		policyViolations.WithLabelValues(policyName, resourceKind, "violation").Inc()
	}
}

// recordCircuitBreakerMetrics records metrics for circuit breaker state changes
func recordCircuitBreakerMetrics(breakerType, state string, failures int) {
	circuitBreakerState.WithLabelValues(state).Set(1)
	if failures > 0 {
		circuitBreakerFailures.WithLabelValues(breakerType).Add(float64(failures))
	}
}
