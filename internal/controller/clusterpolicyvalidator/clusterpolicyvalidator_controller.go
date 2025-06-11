/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package clusterpolicyvalidator

import (
	"context"
	"fmt"
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
	PolicyBlockedAnnotation    = "k8lex.io/policy-blocked"
	OriginalReplicasAnnotation = "k8lex.io/original-replicas"
	BlockedReasonAnnotation    = "k8lex.io/blocked-reason"
	PolicyViolationAnnotation  = "k8lex.io/policy-violation"
	ViolationDetailsAnnotation = "k8lex.io/policy-violation-details"

	// Constants for reconcile behavior
	DefaultRequeueDelay = 30 * time.Second
	MaxRetries          = 3
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
}

// NamespaceFilterState holds the aggregated namespace filtering rules from all policies.
type NamespaceFilterState struct {
	sync.RWMutex
	IncludedNamespaces map[string]struct{}
	ExcludedNamespaces map[string]struct{}
	HasIncludeRules    bool
	HasExcludeRules    bool
}

var globalNamespaceFilter = &NamespaceFilterState{
	IncludedNamespaces: make(map[string]struct{}),
	ExcludedNamespaces: make(map[string]struct{}),
}

// Prometheus metrics
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
}

// UpdateNamespaceFilterState aggregates all namespace rules from existing policies
func (r *ClusterPolicyValidatorReconciler) UpdateNamespaceFilterState(ctx context.Context) error {
	globalNamespaceFilter.Lock()
	defer globalNamespaceFilter.Unlock()

	// Clear previous state
	globalNamespaceFilter.IncludedNamespaces = make(map[string]struct{})
	globalNamespaceFilter.ExcludedNamespaces = make(map[string]struct{})
	globalNamespaceFilter.HasIncludeRules = false
	globalNamespaceFilter.HasExcludeRules = false

	var allPolicies clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorList
	if err := r.List(ctx, &allPolicies); err != nil {
		r.Log.Error(err, "Failed to list ClusterPolicyValidators to update namespace filter state")
		return err
	}

	for _, policy := range allPolicies.Items {
		if len(policy.Spec.Namespaces.Include) > 0 {
			globalNamespaceFilter.HasIncludeRules = true
			for _, ns := range policy.Spec.Namespaces.Include {
				globalNamespaceFilter.IncludedNamespaces[ns] = struct{}{}
			}
		}
		if len(policy.Spec.Namespaces.Exclude) > 0 {
			globalNamespaceFilter.HasExcludeRules = true
			for _, ns := range policy.Spec.Namespaces.Exclude {
				globalNamespaceFilter.ExcludedNamespaces[ns] = struct{}{}
			}
		}
	}

	r.Log.Info("Namespace filter state updated",
		"included_count", len(globalNamespaceFilter.IncludedNamespaces),
		"excluded_count", len(globalNamespaceFilter.ExcludedNamespaces),
		"has_include_rules", globalNamespaceFilter.HasIncludeRules,
		"has_exclude_rules", globalNamespaceFilter.HasExcludeRules,
	)
	return nil
}

// isNamespaceAllowedByPredicate checks if a namespace is allowed based on the current filter state
func isNamespaceAllowedByPredicate(ns string, logger logr.Logger) bool {
	globalNamespaceFilter.RLock()
	defer globalNamespaceFilter.RUnlock()

	if globalNamespaceFilter.HasIncludeRules {
		_, allowed := globalNamespaceFilter.IncludedNamespaces[ns]
		if !allowed {
			logger.V(2).Info("Namespace not in include list", "namespace", ns)
		}
		return allowed
	}

	if globalNamespaceFilter.HasExcludeRules {
		_, excluded := globalNamespaceFilter.ExcludedNamespaces[ns]
		if excluded {
			logger.V(2).Info("Namespace in exclude list", "namespace", ns)
		}
		return !excluded
	}

	return true
}

// namespaceFilteringPredicate returns a predicate that filters events based on namespace rules
func namespaceFilteringPredicate(logger logr.Logger) predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return isNamespaceAllowedByPredicate(e.Object.GetNamespace(), logger)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Only reconcile if the spec has changed AND it's allowed by namespace rules
			if e.ObjectOld != nil && e.ObjectNew != nil &&
				e.ObjectOld.GetGeneration() == e.ObjectNew.GetGeneration() {
				return false
			}
			return isNamespaceAllowedByPredicate(e.ObjectNew.GetNamespace(), logger)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return isNamespaceAllowedByPredicate(e.Object.GetNamespace(), logger)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return isNamespaceAllowedByPredicate(e.Object.GetNamespace(), logger)
		},
	}
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

// evaluatePolicies evaluates all applicable policies against a resource
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

				// If this is a blocking violation, stop processing
				if strings.ToLower(violation.Action) == "block" {
					logger.Info("Block action encountered, stopping evaluation",
						"policy", policy.Name,
						"rule", rule.Name)
					return violations
				}
			}
		}
	}

	return violations
}

// evaluateRule evaluates a single rule against a resource
func (r *ClusterPolicyValidatorReconciler) evaluateRule(
	resource *unstructured.Unstructured,
	policyName string,
	rule clusterpolicyvalidatorv1alpha1.ValidationRule,
	resourceGVK schema.GroupVersionKind,
	logger logr.Logger,
) *ValidationResult {
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
func (r *ClusterPolicyValidatorReconciler) formatErrorMessage(template string, resource client.Object) string {
	if template == "" {
		return "Resource violates policy"
	}

	// Simple template replacement
	message := template
	message = strings.ReplaceAll(message, "{{ .metadata.name }}", resource.GetName())
	message = strings.ReplaceAll(message, "{{ .metadata.namespace }}", resource.GetNamespace())
	message = strings.ReplaceAll(message, "{{ .kind }}", resource.GetObjectKind().GroupVersionKind().Kind)

	return message
}

// SetupWithManager sets up the controller with the Manager
func (r *ClusterPolicyValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize the reconciler
	r.Log = mgr.GetLogger().WithName("clusterpolicyvalidator-controller")
	r.EventRecorder = mgr.GetEventRecorderFor("clusterpolicyvalidator-controller")

	// Initialize caches
	r.jqCache = make(map[string]*gojq.Code)
	r.policyEvalLimiter = make(map[string]*time.Timer)

	// Initial namespace filter update
	if err := r.UpdateNamespaceFilterState(context.Background()); err != nil {
		r.Log.Error(err, "Failed initial namespace filter state update")
		// Don't fail startup, but log the error
	}

	// Build the controller
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 5, // Increased for better throughput
		})

	// Add watches for dynamic resources with namespace filtering
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
		).WithEventFilter(namespaceFilteringPredicate(r.Log))
	}
	return builder.Complete(r)
}

// NewClusterPolicyValidatorReconciler creates a new reconciler
func NewClusterPolicyValidatorReconciler(
	client client.Client,
	scheme *runtime.Scheme,
	watchedResources []ResourceTypeConfig,
) *ClusterPolicyValidatorReconciler {
	return &ClusterPolicyValidatorReconciler{
		Client:            client,
		Scheme:            scheme,
		WatchedResources:  watchedResources,
		jqCache:           make(map[string]*gojq.Code),
		policyEvalLimiter: make(map[string]*time.Timer),
	}
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

	return map[string]interface{}{
		"jq_cache_size":     len(r.jqCache),
		"watched_resources": len(r.WatchedResources),
		"namespace_filter_rules": map[string]interface{}{
			"included_count": len(globalNamespaceFilter.IncludedNamespaces),
			"excluded_count": len(globalNamespaceFilter.ExcludedNamespaces),
			"has_include":    globalNamespaceFilter.HasIncludeRules,
			"has_exclude":    globalNamespaceFilter.HasExcludeRules,
		},
	}
}
