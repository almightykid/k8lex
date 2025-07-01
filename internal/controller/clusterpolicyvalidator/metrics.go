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

	policyViolations = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "clusterpolicyvalidator_violations_total",
			Help: "Total number of policy violations detected by the ClusterPolicyValidator.",
		},
	)

	policyCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "clusterpolicyvalidator_policy_count",
			Help: "Total number of active policies.",
		},
	)
)

func init() {
	metrics.Registry.MustRegister(
		validationAttempts,
		policyViolations,
		policyCount,
	)
}
