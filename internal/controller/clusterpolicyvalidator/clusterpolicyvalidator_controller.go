package clusterpolicyvalidator

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/go-logr/logr"
	"github.com/itchyny/gojq"
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	clusterpolicyvalidatorv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyvalidator/v1alpha1"
)

const (
	// Constants for annotations
	PolicyBlockedAnnotation      = "k8lex.io/policy-blocked"
	OriginalReplicasAnnotation   = "k8lex.io/original-replicas"
	BlockedReasonAnnotation      = "k8lex.io/blocked-reason"
	PolicyViolationAnnotation    = "k8lex.io/policy-violation"
	ViolationDetailsAnnotation   = "k8lex.io/policy-violation-details"
	ConflictResolutionAnnotation = "k8lex.io/policy-conflicts"

	// Constants for reconcile behavior
	DefaultRequeueDelay = 30 * time.Second
	MaxRetries          = 3
	JQCacheMaxSize      = 1000
)

// PolicyConflictResolution defines how to handle policy conflicts
type PolicyConflictResolution string

const (
	ConflictResolutionMostRestrictive PolicyConflictResolution = "most-restrictive"
	ConflictResolutionFirstMatch      PolicyConflictResolution = "first-match"
	ConflictResolutionHighestSeverity PolicyConflictResolution = "highest-severity"
)

// ResourceTypeConfig defines configuration for each resource type
type ResourceTypeConfig struct {
	GVK    schema.GroupVersionKind
	Object client.Object
}

// ValidationResult represents the outcome of a policy validation
type ValidationResult struct {
	PolicyName   string
	RuleName     string
	Violated     bool
	Action       string
	Severity     string
	ErrorMessage string
	ResourcePath string
	Priority     int // For conflict resolution
}

// ClusterPolicyValidatorReconciler reconciles a ClusterPolicyValidator object
type ClusterPolicyValidatorReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	WatchedResources []ResourceTypeConfig
	Log              logr.Logger
	EventRecorder    record.EventRecorder

	// Cache for compiled JQ queries to improve performance
	jqCache   map[string]*gojq.Code
	jqCacheMu sync.RWMutex

	// Rate limiting for policy evaluations
	policyEvalLimiter map[string]*time.Timer
	evalLimiterMu     sync.RWMutex

	// Namespace filtering state - per reconciler instead of global
	namespaceFilter   *NamespaceFilterState
	namespaceFilterMu sync.RWMutex

	// Conflict resolution strategy
	ConflictResolution PolicyConflictResolution
}

// NamespaceFilterState holds the aggregated namespace filtering rules from all policies.
type NamespaceFilterState struct {
	IncludedNamespaces map[string]struct{}
	ExcludedNamespaces map[string]struct{}
	HasIncludeRules    bool
	HasExcludeRules    bool
	LastUpdated        time.Time
}

// Prometheus metrics (keeping existing ones + new ones)
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
}

// FIXED: UpdateNamespaceFilterState - now per-reconciler instead of global
func (r *ClusterPolicyValidatorReconciler) UpdateNamespaceFilterState(ctx context.Context) error {
	r.namespaceFilterMu.Lock()
	defer r.namespaceFilterMu.Unlock()

	// Create new state
	newState := &NamespaceFilterState{
		IncludedNamespaces: make(map[string]struct{}),
		ExcludedNamespaces: make(map[string]struct{}),
		LastUpdated:        time.Now(),
	}

	var allPolicies clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorList
	if err := r.List(ctx, &allPolicies); err != nil {
		r.Log.Error(err, "Failed to list ClusterPolicyValidators to update namespace filter state")
		return err
	}

	r.Log.Info("Updating namespace filter state", "total_policies", len(allPolicies.Items))

	for _, policy := range allPolicies.Items {
		r.Log.V(2).Info("Processing policy namespace rules",
			"policy", policy.Name,
			"include_count", len(policy.Spec.Namespaces.Include),
			"exclude_count", len(policy.Spec.Namespaces.Exclude))

		if len(policy.Spec.Namespaces.Include) > 0 {
			newState.HasIncludeRules = true
			for _, ns := range policy.Spec.Namespaces.Include {
				newState.IncludedNamespaces[ns] = struct{}{}
				r.Log.V(3).Info("Added namespace to include list", "namespace", ns, "policy", policy.Name)
			}
		}
		if len(policy.Spec.Namespaces.Exclude) > 0 {
			newState.HasExcludeRules = true
			for _, ns := range policy.Spec.Namespaces.Exclude {
				newState.ExcludedNamespaces[ns] = struct{}{}
				r.Log.V(3).Info("Added namespace to exclude list", "namespace", ns, "policy", policy.Name)
			}
		}
	}

	// Atomic replacement
	r.namespaceFilter = newState

	r.Log.Info("Namespace filter state updated",
		"included_count", len(newState.IncludedNamespaces),
		"excluded_count", len(newState.ExcludedNamespaces),
		"has_include_rules", newState.HasIncludeRules,
		"has_exclude_rules", newState.HasExcludeRules)

	return nil
}

// ensureNamespaceFilterInitialized ensures the namespace filter is initialized before use
func (r *ClusterPolicyValidatorReconciler) ensureNamespaceFilterInitialized(ctx context.Context) error {
	r.namespaceFilterMu.RLock()
	if r.namespaceFilter != nil && time.Since(r.namespaceFilter.LastUpdated) < 5*time.Minute {
		r.namespaceFilterMu.RUnlock()
		return nil // Recently updated, no need to refresh
	}
	r.namespaceFilterMu.RUnlock()

	// Need to initialize or refresh
	return r.UpdateNamespaceFilterState(ctx)
}

// FIXED: isNamespaceAllowedByPredicate with proper include/exclude precedence
func (r *ClusterPolicyValidatorReconciler) isNamespaceAllowedByPredicate(ns string, logger logr.Logger) bool {
	// Lazy initialization - ensure filter is loaded when first used
	if err := r.ensureNamespaceFilterInitialized(context.Background()); err != nil {
		logger.Error(err, "Failed to initialize namespace filter, allowing all namespaces")
		return true // Fail open
	}

	r.namespaceFilterMu.RLock()
	filter := r.namespaceFilter
	r.namespaceFilterMu.RUnlock()

	if filter == nil {
		logger.V(2).Info("No namespace filter initialized, allowing all", "namespace", ns)
		return true
	}

	// Debug logging
	logger.V(2).Info("Checking namespace filter",
		"namespace", ns,
		"has_include_rules", filter.HasIncludeRules,
		"has_exclude_rules", filter.HasExcludeRules,
		"included_namespaces", len(filter.IncludedNamespaces),
		"excluded_namespaces", len(filter.ExcludedNamespaces))

	// PRECEDENCE RULE: exclude takes absolute precedence over include
	// If a namespace is in exclude list, it's ALWAYS blocked, regardless of include
	if filter.HasExcludeRules {
		if _, excluded := filter.ExcludedNamespaces[ns]; excluded {
			logger.V(1).Info("Namespace BLOCKED by exclude rule (takes precedence)", "namespace", ns)
			namespaceFilteredEvents.WithLabelValues(ns, "excluded", "exclude_rule_precedence").Inc()
			return false
		}
	}

	// If we have include rules, namespace must be explicitly included
	if filter.HasIncludeRules {
		if _, included := filter.IncludedNamespaces[ns]; included {
			logger.V(2).Info("Namespace ALLOWED by include rule", "namespace", ns)
			return true
		} else {
			logger.V(1).Info("Namespace NOT in include list, blocked", "namespace", ns)
			namespaceFilteredEvents.WithLabelValues(ns, "filtered", "not_in_include").Inc()
			return false
		}
	}

	// If only exclude rules exist (no include rules), allow everything not excluded
	if filter.HasExcludeRules && !filter.HasIncludeRules {
		logger.V(2).Info("Namespace allowed (not in exclude list)", "namespace", ns)
		return true
	}

	// If no rules at all, allow everything
	logger.V(2).Info("Namespace allowed (no restrictive rules)", "namespace", ns)
	return true
}

// FIXED: namespaceFilteringPredicate with better Kind detection
func (r *ClusterPolicyValidatorReconciler) namespaceFilteringPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			kind := r.getKindFromObject(e.Object)
			logger := r.Log.WithValues("event", "create", "kind", kind)

			allowed := r.isNamespaceAllowedByPredicate(e.Object.GetNamespace(), logger)
			if !allowed {
				logger.V(1).Info("Create event filtered by namespace",
					"namespace", e.Object.GetNamespace(),
					"name", e.Object.GetName(),
					"kind", kind)
			}
			return allowed
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Skip if object hasn't actually changed (avoid unnecessary reconciles)
			if e.ObjectOld != nil && e.ObjectNew != nil {
				if e.ObjectOld.GetResourceVersion() == e.ObjectNew.GetResourceVersion() {
					return false
				}
				// Only reconcile if the spec has changed OR annotations changed (for our policy annotations)
				if e.ObjectOld.GetGeneration() == e.ObjectNew.GetGeneration() {
					oldAnnotations := e.ObjectOld.GetAnnotations()
					newAnnotations := e.ObjectNew.GetAnnotations()

					// Check if our policy annotations changed
					oldBlocked := ""
					newBlocked := ""
					if oldAnnotations != nil {
						oldBlocked = oldAnnotations[PolicyBlockedAnnotation]
					}
					if newAnnotations != nil {
						newBlocked = newAnnotations[PolicyBlockedAnnotation]
					}

					if oldBlocked == newBlocked {
						return false // No relevant changes
					}
				}
			}

			kind := r.getKindFromObject(e.ObjectNew)
			logger := r.Log.WithValues("event", "update", "kind", kind)

			allowed := r.isNamespaceAllowedByPredicate(e.ObjectNew.GetNamespace(), logger)
			if !allowed {
				logger.V(1).Info("Update event filtered by namespace",
					"namespace", e.ObjectNew.GetNamespace(),
					"name", e.ObjectNew.GetName(),
					"kind", kind)
			}
			return allowed
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			kind := r.getKindFromObject(e.Object)
			logger := r.Log.WithValues("event", "delete", "kind", kind)

			allowed := r.isNamespaceAllowedByPredicate(e.Object.GetNamespace(), logger)
			if !allowed {
				logger.V(1).Info("Delete event filtered by namespace",
					"namespace", e.Object.GetNamespace(),
					"name", e.Object.GetName(),
					"kind", kind)
			}
			return allowed
		},
		GenericFunc: func(e event.GenericEvent) bool {
			kind := r.getKindFromObject(e.Object)
			logger := r.Log.WithValues("event", "generic", "kind", kind)

			allowed := r.isNamespaceAllowedByPredicate(e.Object.GetNamespace(), logger)
			if !allowed {
				logger.V(1).Info("Generic event filtered by namespace",
					"namespace", e.Object.GetNamespace(),
					"name", e.Object.GetName(),
					"kind", kind)
			}
			return allowed
		},
	}
}

// getKindFromObject extracts the Kind from various sources
func (r *ClusterPolicyValidatorReconciler) getKindFromObject(obj client.Object) string {
	// Try to get Kind from ObjectKind first
	if gvk := obj.GetObjectKind().GroupVersionKind(); gvk.Kind != "" {
		return gvk.Kind
	}

	// Fallback: Use reflection to get the type name
	objType := reflect.TypeOf(obj)
	if objType == nil {
		return "Unknown"
	}

	// Remove pointer if it's a pointer type
	if objType.Kind() == reflect.Ptr {
		objType = objType.Elem()
	}

	// Get the type name
	typeName := objType.Name()

	// Handle common k8s types
	switch typeName {
	case "Deployment":
		return "Deployment"
	case "Pod":
		return "Pod"
	case "ReplicaSet":
		return "ReplicaSet"
	case "DaemonSet":
		return "DaemonSet"
	case "StatefulSet":
		return "StatefulSet"
	case "ConfigMap":
		return "ConfigMap"
	case "Secret":
		return "Secret"
	case "Service":
		return "Service"
	case "Ingress":
		return "Ingress"
	case "ClusterPolicyValidator":
		return "ClusterPolicyValidator"
	default:
		return typeName
	}
}

// NEW: Policy conflict resolution
func (r *ClusterPolicyValidatorReconciler) resolveConflicts(violations []ValidationResult, logger logr.Logger) []ValidationResult {
	if len(violations) <= 1 {
		return violations
	}

	// Group violations by resource path
	conflictGroups := make(map[string][]ValidationResult)
	for _, violation := range violations {
		key := violation.ResourcePath
		conflictGroups[key] = append(conflictGroups[key], violation)
	}

	var resolvedViolations []ValidationResult

	for path, group := range conflictGroups {
		if len(group) == 1 {
			resolvedViolations = append(resolvedViolations, group[0])
			continue
		}

		// We have conflicts - resolve them
		logger.Info("Resolving policy conflicts",
			"resource_path", path,
			"conflict_count", len(group),
			"strategy", r.ConflictResolution)

		policyConflicts.WithLabelValues(string(r.ConflictResolution), "unknown").Inc()

		resolved := r.applyConflictResolution(group, logger)
		resolvedViolations = append(resolvedViolations, resolved...)
	}

	return resolvedViolations
}

func (r *ClusterPolicyValidatorReconciler) applyConflictResolution(violations []ValidationResult, logger logr.Logger) []ValidationResult {
	switch r.ConflictResolution {
	case ConflictResolutionMostRestrictive:
		return r.selectMostRestrictive(violations, logger)
	case ConflictResolutionHighestSeverity:
		return r.selectHighestSeverity(violations, logger)
	case ConflictResolutionFirstMatch:
		fallthrough
	default:
		// Return first violation
		return violations[:1]
	}
}

func (r *ClusterPolicyValidatorReconciler) selectMostRestrictive(violations []ValidationResult, logger logr.Logger) []ValidationResult {
	// Priority: block > warn > audit > continue
	actionPriority := map[string]int{
		"block":    4,
		"warn":     3,
		"audit":    2,
		"continue": 1,
	}

	maxPriority := 0
	var mostRestrictive []ValidationResult

	for _, violation := range violations {
		priority := actionPriority[strings.ToLower(violation.Action)]
		if priority > maxPriority {
			maxPriority = priority
			mostRestrictive = []ValidationResult{violation}
		} else if priority == maxPriority {
			mostRestrictive = append(mostRestrictive, violation)
		}
	}

	logger.Info("Selected most restrictive action",
		"action", mostRestrictive[0].Action,
		"selected_count", len(mostRestrictive))

	return mostRestrictive
}

func (r *ClusterPolicyValidatorReconciler) selectHighestSeverity(violations []ValidationResult, logger logr.Logger) []ValidationResult {
	// Priority: critical > high > medium > low
	severityPriority := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
	}

	maxPriority := 0
	var highestSeverity []ValidationResult

	for _, violation := range violations {
		priority := severityPriority[strings.ToLower(violation.Severity)]
		if priority > maxPriority {
			maxPriority = priority
			highestSeverity = []ValidationResult{violation}
		} else if priority == maxPriority {
			highestSeverity = append(highestSeverity, violation)
		}
	}

	logger.Info("Selected highest severity",
		"severity", highestSeverity[0].Severity,
		"selected_count", len(highestSeverity))

	return highestSeverity
}

// Cleanup JQ cache to prevent memory leaks
func (r *ClusterPolicyValidatorReconciler) cleanupJQCache() {
	r.jqCacheMu.Lock()
	defer r.jqCacheMu.Unlock()

	if len(r.jqCache) > JQCacheMaxSize {
		r.Log.Info("Cleaning JQ cache", "current_size", len(r.jqCache), "max_size", JQCacheMaxSize)
		// Keep half the cache, remove the rest
		newCache := make(map[string]*gojq.Code)
		count := 0
		for k, v := range r.jqCache {
			if count < JQCacheMaxSize/2 {
				newCache[k] = v
				count++
			}
		}
		r.jqCache = newCache
	}
}

// Rate limiting implementation
func (r *ClusterPolicyValidatorReconciler) shouldEvaluatePolicy(policyName string) bool {
	r.evalLimiterMu.Lock()
	defer r.evalLimiterMu.Unlock()

	if timer, exists := r.policyEvalLimiter[policyName]; exists {
		select {
		case <-timer.C:
			delete(r.policyEvalLimiter, policyName)
			return true
		default:
			return false // Still rate limited
		}
	}

	// Add rate limiting timer (1 second minimum between evaluations)handleControllerBlocking
	r.policyEvalLimiter[policyName] = time.NewTimer(time.Second)
	return true
}

// Keep all your existing methods but update evaluatePolicies to use conflict resolution
func (r *ClusterPolicyValidatorReconciler) evaluatePolicies(
	ctx context.Context,
	resource *unstructured.Unstructured,
	foundResource client.Object,
	resourceGVK schema.GroupVersionKind,
	policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator,
	logger logr.Logger,
) []ValidationResult {
	var violations []ValidationResult

	for _, policy := range policies {
		if !r.policyAppliesToResource(policy, resourceGVK) {
			continue
		}

		// Add rate limiting check
		if !r.shouldEvaluatePolicy(policy.Name) {
			logger.V(2).Info("Skipping policy evaluation due to rate limiting", "policy", policy.Name)
			continue
		}

		logger.V(1).Info("Evaluating policy",
			"policy", policy.Name,
			"resource", foundResource.GetName(),
			"kind", resourceGVK.Kind)

		policyEvaluationTotal.WithLabelValues(policy.Name, resourceGVK.Kind).Inc()

		for _, rule := range policy.Spec.ValidationRules {
			if !r.ruleAppliesToResource(rule, resourceGVK) {
				continue
			}

			if violation := r.evaluateRule(resource, policy.Name, rule, resourceGVK, logger); violation != nil {
				violations = append(violations, *violation)
			}
		}
	}

	// Clean up cache periodically
	r.cleanupJQCache()

	// Apply conflict resolution
	if len(violations) > 1 {
		violations = r.resolveConflicts(violations, logger)
	}

	// Check if any blocking violations exist after conflict resolution
	for _, violation := range violations {
		if strings.ToLower(violation.Action) == "block" {
			logger.Info("Block action encountered after conflict resolution, stopping evaluation",
				"policy", violation.PolicyName,
				"rule", violation.RuleName)
			return []ValidationResult{violation} // Return only the blocking violation
		}
	}

	return violations
}

// getCompiledJQ returns a compiled JQ query from cache or compiles and caches it
func (r *ClusterPolicyValidatorReconciler) getCompiledJQ(query string) (*gojq.Code, error) {
	r.jqCacheMu.RLock()
	if code, exists := r.jqCache[query]; exists {
		r.jqCacheMu.RUnlock()
		jqCacheHits.Inc()
		return code, nil
	}
	r.jqCacheMu.RUnlock()

	jqCacheMisses.Inc()

	// Parse and compile query
	q, err := gojq.Parse(query)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jq query: %w", err)
	}

	code, err := gojq.Compile(q)
	if err != nil {
		return nil, fmt.Errorf("failed to compile jq query: %w", err)
	}

	// Cache the compiled query
	r.jqCacheMu.Lock()
	if r.jqCache == nil {
		r.jqCache = make(map[string]*gojq.Code)
	}
	r.jqCache[query] = code
	r.jqCacheMu.Unlock()

	return code, nil
}

// extractValues retrieves values for a given field path from the resource
func (r *ClusterPolicyValidatorReconciler) extractValues(resource *unstructured.Unstructured, keyPath string) ([]interface{}, error) {
	// Transform "spec.containers[*].image" to jq-compatible: ".spec.containers[].image"
	jqExpr := "." + strings.ReplaceAll(keyPath, "[*]", "[]")
	jqExpr = fmt.Sprintf("try (%s) catch empty", jqExpr)

	return r.evaluateJQ(resource, jqExpr)
}

// evaluateJQ runs a jq expression on a Kubernetes resource using cached compiled queries
func (r *ClusterPolicyValidatorReconciler) evaluateJQ(resource *unstructured.Unstructured, query string) ([]interface{}, error) {
	code, err := r.getCompiledJQ(query)
	if err != nil {
		return nil, err
	}

	iter := code.Run(resource.Object)
	var results []interface{}

	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, isErr := v.(error); isErr {
			return nil, fmt.Errorf("error running jq query: %w", err)
		}
		results = append(results, v)
	}

	return results, nil
}

// +kubebuilder:rbac:groups=clusterpolicyvalidator.k8lex.io,resources=clusterpolicyvalidators,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=clusterpolicyvalidator.k8lex.io,resources=clusterpolicyvalidators/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=clusterpolicyvalidator.k8lex.io,resources=clusterpolicyvalidators/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods;configmaps;persistentvolumes;persistentvolumeclaims;services;secrets;namespaces,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="apps",resources=deployments;replicasets;daemonsets;statefulsets,verbs=get;list;watch;delete;update
// +kubebuilder:rbac:groups="networking.k8s.io",resources=ingresses,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile is the main kubernetes reconciliation loop
func (r *ClusterPolicyValidatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("ClusterPolicyValidator", req.NamespacedName)
	r.Log = logger

	start := time.Now()
	reconcileResultLabel := "success"

	defer func() {
		reconcileDuration.WithLabelValues("clusterpolicyvalidator", reconcileResultLabel).Observe(time.Since(start).Seconds())
	}()

	// Try to fetch the ClusterPolicyValidator resource
	policy := &clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{}
	err := r.Get(ctx, req.NamespacedName, policy)

	if err == nil {
		// This is a policy change, update namespace filter state
		r.Log.Info("ClusterPolicyValidator reconciled, updating namespace filter state", "policy", policy.Name)
		if err := r.UpdateNamespaceFilterState(ctx); err != nil {
			reconcileResultLabel = "error"
			return ctrl.Result{RequeueAfter: DefaultRequeueDelay}, err
		}
		return ctrl.Result{}, nil
	}

	if !apierrors.IsNotFound(err) {
		r.Log.Error(err, "Unable to fetch ClusterPolicyValidator")
		reconcileResultLabel = "error"
		return ctrl.Result{RequeueAfter: DefaultRequeueDelay}, err
	}

	// This is a resource validation request
	r.Log.V(1).Info("Processing resource validation", "namespacedName", req.NamespacedName)
	result, err := r.validateResource(ctx, req, logger)

	if err != nil {
		reconcileResultLabel = "error"
		// Use exponential backoff for retries
		return ctrl.Result{RequeueAfter: DefaultRequeueDelay}, err
	}

	return result, nil
}

// validateResource validates any Kubernetes resource against all ClusterPolicyValidator policies
func (r *ClusterPolicyValidatorReconciler) validateResource(ctx context.Context, req ctrl.Request, logger logr.Logger) (ctrl.Result, error) {
	validationAttempts.Inc()

	// Find the resource
	foundResource, resourceGVK, err := r.findResource(ctx, req, logger)
	if err != nil {
		return ctrl.Result{}, err
	}
	if foundResource == nil {
		logger.V(2).Info("Resource not found or not watched", "namespacedName", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	resourceProcessedTotal.WithLabelValues(resourceGVK.Kind).Inc()

	// Convert to unstructured for processing
	resource, err := r.convertToUnstructured(foundResource, resourceGVK)
	if err != nil {
		errorTotal.WithLabelValues("failed_to_convert_to_unstructured", resourceGVK.Kind).Inc()
		return ctrl.Result{}, err
	}

	logger.Info("Starting validation",
		"kind", resourceGVK.Kind,
		"name", foundResource.GetName(),
		"namespace", foundResource.GetNamespace())

	// Get all policies
	policies, err := r.listPolicies(ctx)
	if err != nil {
		errorTotal.WithLabelValues("failed_to_list_policies", resourceGVK.Kind).Inc()
		return ctrl.Result{}, err
	}

	// Validate against all applicable policies
	violations := r.evaluatePolicies(ctx, resource, foundResource, resourceGVK, policies, logger)

	// Handle violations
	if len(violations) > 0 {
		return r.handleViolations(ctx, foundResource, resource, resourceGVK, violations, logger)
	}

	// Clear any previous violation annotations if no violations found
	r.clearViolationAnnotations(ctx, resource, logger)

	return ctrl.Result{}, nil
}

// findResource attempts to find the resource across all watched types
func (r *ClusterPolicyValidatorReconciler) findResource(ctx context.Context, req ctrl.Request, logger logr.Logger) (client.Object, schema.GroupVersionKind, error) {
	for _, config := range r.WatchedResources {
		// Skip ClusterPolicyValidator resources
		if config.GVK.Kind == "ClusterPolicyValidator" &&
			config.GVK.Group == clusterpolicyvalidatorv1alpha1.GroupVersion.Group {
			continue
		}

		tempResource := config.Object.DeepCopyObject().(client.Object)
		tempResource.GetObjectKind().SetGroupVersionKind(config.GVK)

		if err := r.Get(ctx, req.NamespacedName, tempResource); err == nil {
			logger.V(2).Info("Found matching resource", "kind", config.GVK.Kind, "name", tempResource.GetName())
			return tempResource, config.GVK, nil
		}
	}

	errorTotal.WithLabelValues("resource_not_found_or_not_watched", "unknown").Inc()
	return nil, schema.GroupVersionKind{}, nil
}

// convertToUnstructured converts a resource to unstructured format
func (r *ClusterPolicyValidatorReconciler) convertToUnstructured(resource client.Object, gvk schema.GroupVersionKind) (*unstructured.Unstructured, error) {
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(resource)
	if err != nil {
		return nil, fmt.Errorf("failed to convert resource to unstructured: %w", err)
	}

	result := &unstructured.Unstructured{Object: unstructuredObj}
	result.SetGroupVersionKind(gvk)
	return result, nil
}

// listPolicies retrieves all ClusterPolicyValidator policies
func (r *ClusterPolicyValidatorReconciler) listPolicies(ctx context.Context) ([]clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator, error) {
	var policies clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorList
	if err := r.List(ctx, &policies); err != nil {
		return nil, fmt.Errorf("failed to list ClusterPolicyValidator policies: %w", err)
	}
	return policies.Items, nil
}

// evaluateRule evaluates a single rule against a resource
func (r *ClusterPolicyValidatorReconciler) evaluateRule(
	resource *unstructured.Unstructured,
	policyName string,
	rule clusterpolicyvalidatorv1alpha1.ValidationRule,
	resourceGVK schema.GroupVersionKind,
	logger logr.Logger,
) *ValidationResult {

	if resource == nil {
		logger.Error(nil, "Resource is nil", "policy", policyName, "rule", rule.Name)
		return nil
	}

	if policyName == "" {
		logger.Error(nil, "Policy name is empty", "rule", rule.Name)
		return nil
	}

	for _, condition := range rule.Conditions {
		if condition.Key == "" {
			logger.Error(nil, "Empty condition key", "rule", rule.Name, "policy", policyName)
			errorTotal.WithLabelValues("empty_condition_key", resourceGVK.Kind).Inc()
			continue
		}

		values, err := r.extractValues(resource, condition.Key)
		if err != nil {
			logger.Error(err, "Failed to extract values", "key", condition.Key, "kind", resourceGVK.Kind)
			errorTotal.WithLabelValues("failed_to_extract_values", resourceGVK.Kind).Inc()
			continue
		}

		if !r.validateCondition(condition, values, logger) {
			logger.Info("Rule violation detected",
				"policy", policyName,
				"rule", rule.Name,
				"condition_key", condition.Key,
				"resource", resource.GetName(),
				"kind", resourceGVK.Kind,
				"severity", rule.Severity)

			return &ValidationResult{
				PolicyName:   policyName,
				RuleName:     rule.Name,
				Violated:     true,
				Action:       rule.Action,
				Severity:     string(rule.Severity),
				ErrorMessage: r.formatErrorMessage(rule.ErrorMessage, resource),
				ResourcePath: condition.Key,
			}
		}
	}

	return nil
}

// validateCondition validates a single condition
func (r *ClusterPolicyValidatorReconciler) validateCondition(
	condition clusterpolicyvalidatorv1alpha1.Condition,
	actualValues []interface{},
	logger logr.Logger,
) bool {
	if len(actualValues) == 0 {
		logger.V(2).Info("No values extracted for condition",
			"operator", condition.Operator,
			"expectedValues", condition.Values)
		return condition.Operator == "IsEmpty"
	}

	switch condition.Operator {
	case "IsEmpty":
		return len(actualValues) == 0
	case "IsNotEmpty":
		return len(actualValues) > 0
	}

	// For other operators, check each actual value
	for _, actualVal := range actualValues {
		actualStr := fmt.Sprintf("%v", actualVal)

		if len(condition.Values) > 0 {
			matchFound := false
			for _, expectedVal := range condition.Values {
				if r.evaluateSingleCondition(actualStr, condition.Operator, expectedVal, logger) {
					matchFound = true
					break
				}
			}
			if !matchFound {
				return false
			}
		} else {
			logger.V(2).Info("No expected values for condition", "operator", condition.Operator)
			return false
		}
	}

	return true
}

// evaluateSingleCondition evaluates a single condition against a value
func (r *ClusterPolicyValidatorReconciler) evaluateSingleCondition(resourceValue, operator, expectedValue string, logger logr.Logger) bool {
	switch operator {
	case "Equals":
		return resourceValue == expectedValue
	case "NotEquals":
		return resourceValue != expectedValue
	case "Contains":
		return strings.Contains(resourceValue, expectedValue)
	case "NotContains":
		return !strings.Contains(resourceValue, expectedValue)
	case "RegexMatch":
		match, err := regexp.MatchString(expectedValue, resourceValue)
		if err != nil {
			logger.Error(err, "Invalid regex pattern", "regex", expectedValue, "value", resourceValue)
			return false
		}
		return match
	case "GreaterThan":
		resourceNum, err1 := strconv.ParseFloat(resourceValue, 64)
		conditionNum, err2 := strconv.ParseFloat(expectedValue, 64)
		return err1 == nil && err2 == nil && resourceNum > conditionNum
	case "LessThan":
		resourceNum, err1 := strconv.ParseFloat(resourceValue, 64)
		conditionNum, err2 := strconv.ParseFloat(expectedValue, 64)
		return err1 == nil && err2 == nil && resourceNum < conditionNum
	default:
		logger.Info("Unknown operator", "operator", operator)
		return false
	}
}

// handleViolations processes all violations for a resource
func (r *ClusterPolicyValidatorReconciler) handleViolations(
	ctx context.Context,
	foundResource client.Object,
	resource *unstructured.Unstructured,
	resourceGVK schema.GroupVersionKind,
	violations []ValidationResult,
	logger logr.Logger,
) (ctrl.Result, error) {
	for _, violation := range violations {
		// Record metrics
		policyViolations.WithLabelValues(violation.PolicyName, resourceGVK.Kind, violation.Severity).Inc()
		actionTakenTotal.WithLabelValues(violation.Action, resourceGVK.Kind, violation.Severity).Inc()

		// Take action based on violation
		if err := r.handleResourceAction(ctx, foundResource, resourceGVK.Kind, violation, logger); err != nil {
			return ctrl.Result{RequeueAfter: DefaultRequeueDelay}, err
		}

		// For blocking actions, stop processing immediately
		if strings.ToLower(violation.Action) == "block" {
			logger.Info("Resource blocked due to policy violation",
				"policy", violation.PolicyName,
				"rule", violation.RuleName,
				"resource", foundResource.GetName())
			return ctrl.Result{}, nil
		}
	}

	// Update resource annotations with violation details
	return ctrl.Result{}, r.updateViolationAnnotations(ctx, resource, violations, logger)
}

// handleResourceAction takes action on a resource based on policy violation
func (r *ClusterPolicyValidatorReconciler) handleResourceAction(
	ctx context.Context,
	resource client.Object,
	kind string,
	violation ValidationResult,
	logger logr.Logger,
) error {
	resourceName := resource.GetName()
	namespace := resource.GetNamespace()

	logger.Info("Taking action for policy violation",
		"resource", resourceName,
		"namespace", namespace,
		"kind", kind,
		"policy", violation.PolicyName,
		"rule", violation.RuleName,
		"action", violation.Action,
		"severity", violation.Severity)

	switch strings.ToLower(violation.Action) {
	case "block":
		return r.handleBlockAction(ctx, resource, kind, violation, logger)
	case "warn":
		return r.handleWarnAction(ctx, resource, violation, logger)
	case "audit":
		return r.handleAuditAction(ctx, resource, violation, logger)
	case "continue":
		// Just log, no action needed
		return nil
	default:
		logger.Info("Unknown action type", "action", violation.Action)
		return nil
	}
}

// handleBlockAction handles blocking actions for policy violations
func (r *ClusterPolicyValidatorReconciler) handleBlockAction(
	ctx context.Context,
	resource client.Object,
	kind string,
	violation ValidationResult,
	logger logr.Logger,
) error {
	switch kind {
	case "Pod":
		return r.handlePodBlocking(ctx, resource, violation, logger)
	case "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet":
		return r.handleControllerBlocking(ctx, resource, violation, logger)
	default:
		return r.handleGenericResourceBlocking(ctx, resource, violation, logger)
	}
}

// handlePodBlocking handles blocking of pod resources
func (r *ClusterPolicyValidatorReconciler) handlePodBlocking(
	ctx context.Context,
	resource client.Object,
	violation ValidationResult,
	logger logr.Logger,
) error {
	// Check if pod is managed by a controller
	if ownerRefs := resource.GetOwnerReferences(); len(ownerRefs) > 0 {
		for _, ownerRef := range ownerRefs {
			if ownerRef.Kind == "ReplicaSet" {
				logger.Info("Pod managed by ReplicaSet, handling parent deployment",
					"pod", resource.GetName(),
					"replicaSet", ownerRef.Name)
				return r.handleDeploymentViolation(ctx, resource.GetNamespace(), ownerRef.Name, violation, logger)
			}
		}
	}

	// Standalone pod - delete it directly
	logger.Info("Deleting standalone pod due to policy violation", "pod", resource.GetName())
	if err := r.Delete(ctx, resource); client.IgnoreNotFound(err) != nil {
		logger.Error(err, "Failed to delete pod", "pod", resource.GetName())
		errorTotal.WithLabelValues("failed_to_delete_pod", "Pod").Inc()
		return err
	}

	r.EventRecorder.Eventf(resource, corev1.EventTypeWarning, "PolicyViolation",
		"Pod %s deleted due to policy violation: %s", resource.GetName(), violation.ErrorMessage)

	return nil
}

// handleControllerBlocking handles blocking of controller resources (Deployments, etc.)
func (r *ClusterPolicyValidatorReconciler) handleControllerBlocking(
	ctx context.Context,
	resource client.Object,
	violation ValidationResult,
	logger logr.Logger,
) error {
	unstructuredObj, ok := resource.(*unstructured.Unstructured)
	if !ok {
		// Convert to unstructured if needed
		converted, err := runtime.DefaultUnstructuredConverter.ToUnstructured(resource)
		if err != nil {
			return fmt.Errorf("failed to convert resource to unstructured: %w", err)
		}
		unstructuredObj = &unstructured.Unstructured{Object: converted}
		unstructuredObj.SetGroupVersionKind(resource.GetObjectKind().GroupVersionKind())
	}

	// Get current replicas
	var currentReplicas int32
	if replicas, found, err := unstructured.NestedInt64(unstructuredObj.Object, "spec", "replicas"); err == nil && found {
		currentReplicas = int32(replicas)
	} else {
		currentReplicas = 1 // Default assumption
	}

	if currentReplicas == 0 {
		logger.Info("Resource already scaled to 0, marking as policy-blocked",
			"kind", unstructuredObj.GetKind(),
			"resource", resource.GetName())
	} else {
		// Scale to zero
		if err := unstructured.SetNestedField(unstructuredObj.Object, int64(0), "spec", "replicas"); err != nil {
			logger.Error(err, "Failed to set replicas to 0",
				"kind", unstructuredObj.GetKind(),
				"resource", resource.GetName())
			errorTotal.WithLabelValues("failed_set_replicas_to_zero", unstructuredObj.GetKind()).Inc()
			return err
		}
		logger.Info("Scaling resource to 0 due to policy violation",
			"kind", unstructuredObj.GetKind(),
			"resource", resource.GetName(),
			"originalReplicas", currentReplicas)
	}

	// Add blocking annotations
	annotations := resource.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[PolicyBlockedAnnotation] = "true"
	annotations[OriginalReplicasAnnotation] = fmt.Sprintf("%d", currentReplicas)
	annotations[BlockedReasonAnnotation] = violation.ErrorMessage
	resource.SetAnnotations(annotations)

	if err := r.Update(ctx, unstructuredObj); err != nil {
		logger.Error(err, "Failed to scale down and annotate resource",
			"kind", unstructuredObj.GetKind(),
			"resource", resource.GetName())
		errorTotal.WithLabelValues("failed_scale_down_and_annotate", unstructuredObj.GetKind()).Inc()
		return err
	}

	r.EventRecorder.Eventf(resource, corev1.EventTypeWarning, "PolicyViolation",
		"Resource %s scaled to 0 due to policy violation: %s", resource.GetName(), violation.ErrorMessage)

	return nil
}

// handleGenericResourceBlocking handles blocking of generic resources
func (r *ClusterPolicyValidatorReconciler) handleGenericResourceBlocking(
	ctx context.Context,
	resource client.Object,
	violation ValidationResult,
	logger logr.Logger,
) error {
	logger.Info("Deleting resource due to policy violation",
		"kind", resource.GetObjectKind().GroupVersionKind().Kind,
		"resource", resource.GetName())

	if err := r.Delete(ctx, resource); client.IgnoreNotFound(err) != nil {
		logger.Error(err, "Failed to delete resource",
			"kind", resource.GetObjectKind().GroupVersionKind().Kind,
			"resource", resource.GetName())
		errorTotal.WithLabelValues("failed_to_delete_resource", resource.GetObjectKind().GroupVersionKind().Kind).Inc()
		return err
	}

	r.EventRecorder.Eventf(resource, corev1.EventTypeWarning, "PolicyViolation",
		"Resource %s deleted due to policy violation: %s", resource.GetName(), violation.ErrorMessage)

	return nil
}

// handleWarnAction handles warning actions for policy violations
func (r *ClusterPolicyValidatorReconciler) handleWarnAction(
	ctx context.Context,
	resource client.Object,
	violation ValidationResult,
	logger logr.Logger,
) error {
	r.EventRecorder.Eventf(resource, corev1.EventTypeWarning, "PolicyViolation",
		"Policy violation detected for resource %s: %s", resource.GetName(), violation.ErrorMessage)
	return nil
}

// handleAuditAction handles audit actions for policy violations
func (r *ClusterPolicyValidatorReconciler) handleAuditAction(
	ctx context.Context,
	resource client.Object,
	violation ValidationResult,
	logger logr.Logger,
) error {
	r.EventRecorder.Eventf(resource, corev1.EventTypeNormal, "PolicyAudit",
		"Policy audit: Resource %s flagged by policy %s", resource.GetName(), violation.PolicyName)
	return nil
}

// handleDeploymentViolation finds and handles the parent deployment
func (r *ClusterPolicyValidatorReconciler) handleDeploymentViolation(
	ctx context.Context,
	namespace, replicaSetName string,
	violation ValidationResult,
	logger logr.Logger,
) error {
	// Get the ReplicaSet
	replicaSet := &appsv1.ReplicaSet{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: replicaSetName}, replicaSet); err != nil {
		return fmt.Errorf("failed to get ReplicaSet %s: %w", replicaSetName, err)
	}

	// Find parent Deployment
	for _, ownerRef := range replicaSet.GetOwnerReferences() {
		if ownerRef.Kind == "Deployment" {
			deploymentName := ownerRef.Name
			logger.Info("Found parent deployment", "deployment", deploymentName)

			deployment := &appsv1.Deployment{}
			if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: deploymentName}, deployment); err != nil {
				return fmt.Errorf("failed to get Deployment %s: %w", deploymentName, err)
			}

			// Check if already blocked
			if deployment.Annotations != nil {
				if blocked, exists := deployment.Annotations[PolicyBlockedAnnotation]; exists && blocked == "true" {
					logger.Info("Deployment already blocked", "deployment", deploymentName)
					return nil
				}
			}

			// Handle deployment blocking
			return r.handleControllerBlocking(ctx, deployment, violation, logger)
		}
	}

	return fmt.Errorf("no parent Deployment found for ReplicaSet %s", replicaSetName)
}

// updateViolationAnnotations updates resource annotations with violation details
func (r *ClusterPolicyValidatorReconciler) updateViolationAnnotations(
	ctx context.Context,
	resource *unstructured.Unstructured,
	violations []ValidationResult,
	logger logr.Logger,
) error {
	annotations := resource.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}

	if len(violations) > 0 {
		annotations[PolicyViolationAnnotation] = "true"

		// Aggregate violation details
		var details []string
		for _, v := range violations {
			detail := fmt.Sprintf("Policy: %s, Rule: %s, Severity: %s, Message: %s",
				v.PolicyName, v.RuleName, v.Severity, v.ErrorMessage)
			details = append(details, detail)
		}
		annotations[ViolationDetailsAnnotation] = strings.Join(details, "; ")
	} else {
		// Clear violation annotations
		delete(annotations, PolicyViolationAnnotation)
		delete(annotations, ViolationDetailsAnnotation)
	}

	resource.SetAnnotations(annotations)

	if err := r.Update(ctx, resource); err != nil {
		logger.Error(err, "Failed to update resource annotations",
			"name", resource.GetName(),
			"namespace", resource.GetNamespace())
		errorTotal.WithLabelValues("failed_update_resource_annotations", resource.GetKind()).Inc()
		return err
	}

	return nil
}

// clearViolationAnnotations removes violation annotations from a resource
func (r *ClusterPolicyValidatorReconciler) clearViolationAnnotations(
	ctx context.Context,
	resource *unstructured.Unstructured,
	logger logr.Logger,
) {
	annotations := resource.GetAnnotations()
	if annotations == nil {
		return
	}

	// Check if violation annotations exist
	if _, exists := annotations[PolicyViolationAnnotation]; !exists {
		return
	}

	// Remove violation annotations
	delete(annotations, PolicyViolationAnnotation)
	delete(annotations, ViolationDetailsAnnotation)
	resource.SetAnnotations(annotations)

	if err := r.Update(ctx, resource); err != nil {
		logger.Error(err, "Failed to clear violation annotations",
			"name", resource.GetName(),
			"namespace", resource.GetNamespace())
		errorTotal.WithLabelValues("failed_clear_violation_annotations", resource.GetKind()).Inc()
	} else {
		logger.V(1).Info("Cleared violation annotations",
			"name", resource.GetName(),
			"namespace", resource.GetNamespace())
	}
}

// policyAppliesToResource checks if a policy applies to a resource type
func (r *ClusterPolicyValidatorReconciler) policyAppliesToResource(
	policy clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator,
	resourceGVK schema.GroupVersionKind,
) bool {
	for _, rule := range policy.Spec.ValidationRules {
		if r.ruleAppliesToResource(rule, resourceGVK) {
			return true
		}
	}
	return false
}

// ruleAppliesToResource checks if a rule applies to a resource type
func (r *ClusterPolicyValidatorReconciler) ruleAppliesToResource(
	rule clusterpolicyvalidatorv1alpha1.ValidationRule,
	resourceGVK schema.GroupVersionKind,
) bool {
	// If no kinds specified, rule applies to all resources
	if len(rule.MatchResources.Kinds) == 0 {
		return true
	}

	// Check if resource kind matches any in the rule
	for _, kind := range rule.MatchResources.Kinds {
		if strings.EqualFold(kind, resourceGVK.Kind) {
			return true
		}
	}

	return false
}

// formatErrorMessage formats the error message with resource context
func (r *ClusterPolicyValidatorReconciler) formatErrorMessage(template string, resource *unstructured.Unstructured) string {
	if template == "" {
		return "Resource violates policy"
	}

	message := template
	message = strings.ReplaceAll(message, "{{ .metadata.name }}", resource.GetName())
	message = strings.ReplaceAll(message, "{{ .metadata.namespace }}", resource.GetNamespace())

	// Mejor manera de obtener el Kind
	kind := resource.GetKind()
	if kind == "" {
		kind = "Unknown"
	}
	message = strings.ReplaceAll(message, "{{ .kind }}", kind)

	return message
}

// HealthCheck provides a health check endpoint for the controller
func (r *ClusterPolicyValidatorReconciler) HealthCheck() error {
	// Basic health check - verify we can list policies
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var policies clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorList
	if err := r.List(ctx, &policies); err != nil {
		return fmt.Errorf("health check failed: unable to list policies: %w", err)
	}

	return nil
}

// GetMetrics returns current metrics for monitoring
func (r *ClusterPolicyValidatorReconciler) GetMetrics() map[string]interface{} {
	r.jqCacheMu.RLock()
	defer r.jqCacheMu.RUnlock()

	r.namespaceFilterMu.RLock()
	defer r.namespaceFilterMu.RUnlock()

	return map[string]interface{}{
		"jq_cache_size":     len(r.jqCache),
		"watched_resources": len(r.WatchedResources),
		"namespace_filter_rules": map[string]interface{}{
			"included_count": len(r.namespaceFilter.IncludedNamespaces),
			"excluded_count": len(r.namespaceFilter.ExcludedNamespaces),
			"has_include":    r.namespaceFilter.HasIncludeRules,
			"has_exclude":    r.namespaceFilter.HasExcludeRules,
			"last_updated":   r.namespaceFilter.LastUpdated,
		},
		"conflict_resolution": r.ConflictResolution,
	}
}

// Update SetupWithManager to use the new predicate
func (r *ClusterPolicyValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize the reconciler
	r.Log = mgr.GetLogger().WithName("clusterpolicyvalidator-controller")
	r.EventRecorder = mgr.GetEventRecorderFor("clusterpolicyvalidator-controller")

	// Initialize caches and state
	r.jqCache = make(map[string]*gojq.Code)
	r.policyEvalLimiter = make(map[string]*time.Timer)
	r.namespaceFilter = &NamespaceFilterState{
		IncludedNamespaces: make(map[string]struct{}),
		ExcludedNamespaces: make(map[string]struct{}),
	}

	// Set default conflict resolution strategy
	if r.ConflictResolution == "" {
		r.ConflictResolution = ConflictResolutionMostRestrictive
	}

	// Note: Don't update namespace filter state here as the cache isn't started yet
	// It will be updated on the first policy reconciliation

	// Build the controller
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 5,
		})

	// Add watches for dynamic resources with FIXED namespace filtering
	for _, config := range r.WatchedResources {
		// Skip ClusterPolicyValidator as it's already watched
		if config.GVK.Kind == "ClusterPolicyValidator" &&
			config.GVK.Group == clusterpolicyvalidatorv1alpha1.GroupVersion.Group {
			continue
		}

		r.Log.Info("Setting up watch with namespace filtering", "GVK", config.GVK)
		builder = builder.Watches(
			config.Object,
			&handler.EnqueueRequestForObject{},
		).WithEventFilter(r.namespaceFilteringPredicate()) // Use instance method
	}

	return builder.Complete(r)
}

// Update constructor to initialize conflict resolution
func NewClusterPolicyValidatorReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	watchedResources []ResourceTypeConfig,
) *ClusterPolicyValidatorReconciler {
	return &ClusterPolicyValidatorReconciler{
		Client:             client,
		Scheme:             scheme,
		WatchedResources:   watchedResources,
		jqCache:            make(map[string]*gojq.Code),
		policyEvalLimiter:  make(map[string]*time.Timer),
		ConflictResolution: ConflictResolutionMostRestrictive, // Default strategy
		namespaceFilter: &NamespaceFilterState{
			IncludedNamespaces: make(map[string]struct{}),
			ExcludedNamespaces: make(map[string]struct{}),
		},
	}
}
