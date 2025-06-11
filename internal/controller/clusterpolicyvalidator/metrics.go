package clusterpolicyvalidator

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	validationAttempts = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_validation_total",
			Help: "Total number of resources validation attempts by the ClusterPolicyValidator.",
		},
	)

	policyViolations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_violations_total",
			Help: "Total number of policy violations detected by the ClusterPolicyValidator.",
		},
		[]string{"policy_name", "resource_kind", "severity"},
	)

	reconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "clusterpolicyvalidator_reconcile_duration_seconds",
			Help:    "Histogram of reconcile durations for ClusterPolicyValidator.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"controller", "result"},
	)

	policyEvaluationTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_policy_evaluation_total",
			Help: "Total number of times a ClusterPolicyValidator policy was evaluated against a resource.",
		},
		[]string{"policy_name", "resource_kind"},
	)

	actionTakenTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_action_taken_total",
			Help: "Total number of actions (block, warn, continue) taken by the ClusterPolicyValidator.",
		},
		[]string{"action_type", "resource_kind", "severity"},
	)

	resourceProcessedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_resource_processed_total",
			Help: "Total number of resources successfully processed by the ClusterPolicyValidator reconciler.",
		},
		[]string{"resource_kind"},
	)

	errorTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_error_total",
			Help: "Total number of errors encountered during ClusterPolicyValidator operations.",
		},
		[]string{"error_type", "resource_kind"},
	)

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

	namespaceFilteredEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_namespace_filtered_events_total",
			Help: "Total number of events filtered by namespace rules.",
		},
		[]string{"namespace", "action", "reason"},
	)

	policyConflicts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_policy_conflicts_total",
			Help: "Total number of policy conflicts detected.",
		},
		[]string{"resolution_strategy", "resource_kind"},
	)

	// NEW: Enhanced metrics for performance monitoring
	retryAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_retry_attempts_total",
			Help: "Total number of retry attempts for failed operations.",
		},
		[]string{"operation", "attempt"},
	)

	circuitBreakerState = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clusterpolicyvalidator_circuit_breaker_state",
			Help: "Current state of circuit breakers (0=closed, 1=open, 2=half-open).",
		},
		[]string{"breaker_type"},
	)

	cacheSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clusterpolicyvalidator_cache_size",
			Help: "Current size of various caches.",
		},
		[]string{"cache_type"},
	)

	cacheHitRatio = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clusterpolicyvalidator_cache_hit_ratio",
			Help: "Cache hit ratio for various caches.",
		},
		[]string{"cache_type"},
	)

	evaluationLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "clusterpolicyvalidator_evaluation_duration_seconds",
			Help:    "Histogram of policy evaluation durations.",
			Buckets: []float64{0.001, 0.01, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0},
		},
		[]string{"policy_name", "resource_kind"},
	)

	concurrentEvaluations = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "clusterpolicyvalidator_concurrent_evaluations",
			Help: "Current number of concurrent policy evaluations.",
		},
	)

	failureMode = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "clusterpolicyvalidator_failure_mode",
			Help: "Current failure mode (0=fail-safe, 1=fail-secure).",
		},
		[]string{"mode"},
	)

	policyBypassTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_policy_bypass_total",
			Help: "Total number of policy bypasses.",
		},
		[]string{"bypass_type", "resource_kind"},
	)
)

func init() {
	metrics.Registry.MustRegister(validationAttempts)
	metrics.Registry.MustRegister(policyViolations)
	metrics.Registry.MustRegister(reconcileDuration)
	metrics.Registry.MustRegister(policyEvaluationTotal)
	metrics.Registry.MustRegister(actionTakenTotal)
	metrics.Registry.MustRegister(resourceProcessedTotal)
	metrics.Registry.MustRegister(errorTotal)
	metrics.Registry.MustRegister(jqCacheHits)
	metrics.Registry.MustRegister(jqCacheMisses)
	metrics.Registry.MustRegister(namespaceFilteredEvents)
	metrics.Registry.MustRegister(policyConflicts)
	metrics.Registry.MustRegister(retryAttempts)
	metrics.Registry.MustRegister(circuitBreakerState)
	metrics.Registry.MustRegister(cacheSize)
	metrics.Registry.MustRegister(cacheHitRatio)
	metrics.Registry.MustRegister(evaluationLatency)
	metrics.Registry.MustRegister(concurrentEvaluations)
	metrics.Registry.MustRegister(failureMode)
	metrics.Registry.MustRegister(policyBypassTotal)
}
