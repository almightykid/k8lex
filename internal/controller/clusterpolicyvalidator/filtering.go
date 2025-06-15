package clusterpolicyvalidator

import (
	"context"
	"time"

	clusterpolicyvalidatorv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyvalidator/v1alpha1"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// UpdateNamespaceFilterState rebuilds the namespace filtering rules from all policies with retry protection
// This method aggregates namespace inclusion and exclusion rules from all ClusterPolicyValidator policies
// to create a unified filtering state. It implements retry logic to handle transient API failures gracefully
func (r *ClusterPolicyValidatorReconciler) UpdateNamespaceFilterState(ctx context.Context) error {
	return r.retryWithBackoff(ctx, func() error {
		// Acquire exclusive lock to ensure atomic state updates during concurrent operations
		r.namespaceFilterMu.Lock()
		defer r.namespaceFilterMu.Unlock()

		r.Log.V(2).Info("Starting namespace filter state update from all policies")

		// Create fresh state to replace current state atomically, preventing partial updates
		newState := &NamespaceFilterState{
			IncludedNamespaces: make(map[string]struct{}),
			ExcludedNamespaces: make(map[string]struct{}),
			LastUpdated:        time.Now(),
		}

		// Fetch all current ClusterPolicyValidator policies from the Kubernetes API
		var allPolicies clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorList
		if err := r.List(ctx, &allPolicies); err != nil {
			r.Log.Error(err, "Failed to list ClusterPolicyValidators during namespace filter update")
			return err
		}

		// Aggregate namespace rules from each policy to build comprehensive filter state
		for _, policy := range allPolicies.Items {
			r.Log.Info("Processing namespace filtering for policy",
				"policy_name", policy.Name,
				"policy_namespace", policy.Namespace,
				"policy_generation", policy.Generation,
				"include_namespaces", len(policy.Spec.Namespaces.Include),
				"exclude_namespaces", len(policy.Spec.Namespaces.Exclude))

			// Process namespace inclusion rules - these define allowed namespaces
			if len(policy.Spec.Namespaces.Include) > 0 {
				newState.HasIncludeRules = true
				for _, ns := range policy.Spec.Namespaces.Include {
					newState.IncludedNamespaces[ns] = struct{}{}
					r.Log.V(3).Info("Added namespace to inclusion list",
						"namespace", ns,
						"policy", policy.Name,
						"rule_type", "include")
				}
			}

			// Process namespace exclusion rules - these define forbidden namespaces
			if len(policy.Spec.Namespaces.Exclude) > 0 {
				newState.HasExcludeRules = true
				for _, ns := range policy.Spec.Namespaces.Exclude {
					newState.ExcludedNamespaces[ns] = struct{}{}
					r.Log.V(3).Info("Added namespace to exclusion list",
						"namespace", ns,
						"policy", policy.Name,
						"rule_type", "exclude")
				}
			}
		}

		// Atomically replace the current namespace filter state to prevent inconsistencies
		r.namespaceFilter = newState

		r.Log.Info("Namespace filter state updated successfully",
			"included_namespaces", len(newState.IncludedNamespaces),
			"excluded_namespaces", len(newState.ExcludedNamespaces),
			"has_include_rules", newState.HasIncludeRules,
			"has_exclude_rules", newState.HasExcludeRules)

		return nil
	}, "api-update-namespace-filter")
}

// ensureNamespaceFilterInitialized performs lazy initialization and cache-aware refresh of namespace filter state
// This method implements intelligent caching with TTL to avoid unnecessary API calls while ensuring data freshness
// It uses a 5-minute cache TTL to balance performance with consistency
func (r *ClusterPolicyValidatorReconciler) ensureNamespaceFilterInitialized(ctx context.Context) error {
	// Check if current filter state is recent enough to avoid unnecessary API calls
	r.namespaceFilterMu.RLock()
	if r.namespaceFilter != nil && time.Since(r.namespaceFilter.LastUpdated) < 5*time.Minute {
		r.namespaceFilterMu.RUnlock()
		r.Log.V(3).Info("Namespace filter state is recent - skipping refresh",
			"last_updated", r.namespaceFilter.LastUpdated,
			"cache_ttl", "5m")
		return nil // State is fresh enough, no refresh needed
	}
	r.namespaceFilterMu.RUnlock()

	// State is stale or uninitialized - refresh from Kubernetes API
	r.Log.V(2).Info("Namespace filter state requires refresh - updating from policies")
	return r.UpdateNamespaceFilterState(ctx)
}

// isNamespaceAllowedByPredicate determines if a namespace should be processed based on aggregated policy rules
// This method implements the core namespace filtering logic with proper precedence handling:
// CRITICAL PRECEDENCE RULE: Exclude rules ALWAYS take precedence over include rules for security
func (r *ClusterPolicyValidatorReconciler) isNamespaceAllowedByPredicate(ns string, logger logr.Logger) bool {
	// Ensure namespace filter is initialized before making filtering decisions
	if err := r.ensureNamespaceFilterInitialized(context.Background()); err != nil {
		logger.Error(err, "Failed to initialize namespace filter - failing open for availability",
			"namespace", ns,
			"fallback_behavior", "allow_all")
		return true // Fail open to maintain system availability
	}

	// Safely read current filter state with appropriate locking
	r.namespaceFilterMu.RLock()
	filter := r.namespaceFilter
	r.namespaceFilterMu.RUnlock()

	// Handle uninitialized filter state gracefully
	if filter == nil {
		logger.V(2).Info("No namespace filter configured - allowing all namespaces",
			"namespace", ns,
			"behavior", "allow_all")
		return true
	}

	logger.V(2).Info("Evaluating namespace against filtering rules",
		"namespace", ns,
		"has_include_rules", filter.HasIncludeRules,
		"has_exclude_rules", filter.HasExcludeRules,
		"total_included", len(filter.IncludedNamespaces),
		"total_excluded", len(filter.ExcludedNamespaces),
		"last_updated", filter.LastUpdated)

	// SECURITY-CRITICAL: Exclude rules take absolute precedence over include rules
	// If a namespace is explicitly excluded, it's ALWAYS blocked regardless of include rules
	// This ensures that security policies cannot be bypassed through conflicting rules
	if filter.HasExcludeRules {
		if _, excluded := filter.ExcludedNamespaces[ns]; excluded {
			logger.V(1).Info("Namespace blocked by exclusion rule - takes precedence over any inclusion rules",
				"namespace", ns,
				"rule_type", "exclude",
				"precedence", "absolute")
			namespaceFilteredEvents.WithLabelValues(ns, "excluded", "exclude_rule_precedence").Inc()
			return false
		}
	}

	// If include rules exist, namespace must be explicitly included to be allowed
	if filter.HasIncludeRules {
		if _, included := filter.IncludedNamespaces[ns]; included {
			logger.V(2).Info("Namespace allowed by inclusion rule",
				"namespace", ns,
				"rule_type", "include",
				"status", "allowed")
			return true
		} else {
			logger.V(1).Info("Namespace not in inclusion list - blocked by default",
				"namespace", ns,
				"rule_type", "include_missing",
				"status", "blocked")
			namespaceFilteredEvents.WithLabelValues(ns, "filtered", "not_in_include_list").Inc()
			return false
		}
	}

	// Only exclude rules exist (no include rules): allow everything not explicitly excluded
	if filter.HasExcludeRules && !filter.HasIncludeRules {
		logger.V(2).Info("Namespace allowed - not in exclusion list and no inclusion restrictions",
			"namespace", ns,
			"rule_type", "exclude_only",
			"status", "allowed")
		return true
	}

	// No filtering rules configured: allow everything (open policy)
	logger.V(2).Info("Namespace allowed - no filtering rules configured",
		"namespace", ns,
		"rule_type", "none",
		"status", "allowed")
	return true
}

// optimizedEventFilter creates an intelligent event filtering predicate that reduces unnecessary reconciliations
// This filter implements multiple optimization strategies:
// 1. Namespace-based filtering using aggregated policy rules
// 2. Generation-based change detection to skip status-only updates
// 3. Policy bypass detection to honor emergency annotations
// 4. Resource version comparison to eliminate duplicate events
func (r *ClusterPolicyValidatorReconciler) optimizedEventFilter() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return r.shouldProcessEvent(e.Object, "create")
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Implement intelligent update filtering to reduce reconciliation load
			if e.ObjectOld != nil && e.ObjectNew != nil {
				// Skip if resource version hasn't changed (indicates no actual modification)
				if e.ObjectOld.GetResourceVersion() == e.ObjectNew.GetResourceVersion() {
					return false
				}

				// Only process if spec changed (generation increment) OR policy annotations changed
				// This filters out status-only updates that don't require policy evaluation
				if e.ObjectOld.GetGeneration() == e.ObjectNew.GetGeneration() {
					if !r.relevantAnnotationsChanged(e.ObjectOld, e.ObjectNew) {
						return false // Status-only update, skip processing
					}
				}
			}

			return r.shouldProcessEvent(e.ObjectNew, "update")
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			// Always process delete events if namespace is allowed (for cleanup operations)
			kind := r.getKindFromObject(e.Object)
			logger := r.Log.WithValues("event", "delete", "kind", kind)

			allowed := r.isNamespaceAllowedByPredicate(e.Object.GetNamespace(), logger)
			if !allowed {
				logger.V(2).Info("Delete event filtered due to namespace restrictions",
					"resource", e.Object.GetName(),
					"namespace", e.Object.GetNamespace())
			}
			return allowed
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return r.shouldProcessEvent(e.Object, "generic")
		},
	}
}

// shouldProcessEvent determines if a Kubernetes event should trigger a reconciliation
// This method consolidates all event filtering logic including namespace filtering,
// policy bypass detection, and resource type validation
func (r *ClusterPolicyValidatorReconciler) shouldProcessEvent(obj client.Object, eventType string) bool {
	kind := r.getKindFromObject(obj)
	logger := r.Log.WithValues(
		"event_type", eventType,
		"resource_kind", kind,
		"resource_name", obj.GetName(),
		"resource_namespace", obj.GetNamespace())

	logger.V(3).Info("Evaluating event for processing",
		"filters", "namespace,bypass,policy_relevance")

	// First filter: Check if namespace is allowed by current policy configuration
	if !r.isNamespaceAllowedByPredicate(obj.GetNamespace(), logger) {
		logger.V(2).Info("Event filtered due to namespace restrictions",
			"filter_reason", "namespace_not_allowed",
			"namespace", obj.GetNamespace())
		return false
	}

	// Second filter: Check if resource has policy bypass annotations
	if r.shouldBypassPolicies(obj) {
		logger.V(2).Info("Event filtered due to policy bypass annotation",
			"filter_reason", "policy_bypass_detected",
			"bypass_type", "annotation_based")
		return false
	}

	logger.V(3).Info("Event approved for processing - passed all filters",
		"decision", "process",
		"filters_passed", "namespace,bypass,policy_relevance")
	return true
}

// relevantAnnotationsChanged detects changes in policy-related annotations to optimize update processing
// This method implements smart filtering by only triggering reconciliation when annotations that affect
// policy enforcement have actually changed, reducing unnecessary processing overhead
func (r *ClusterPolicyValidatorReconciler) relevantAnnotationsChanged(oldObj, newObj client.Object) bool {
	oldAnnotations := oldObj.GetAnnotations()
	newAnnotations := newObj.GetAnnotations()

	// Define annotations that are relevant to policy enforcement and should trigger reconciliation
	relevantAnnotations := []string{
		PolicyBlockedAnnotation,   // Indicates if resource is currently blocked by policy
		PolicyViolationAnnotation, // Marks resources with active policy violations
		PolicyBypassAnnotation,    // Regular policy bypass for maintenance operations
		EmergencyBypassAnnotation, // Emergency policy bypass for critical situations
	}

	// Check each relevant annotation for value changes
	for _, annotation := range relevantAnnotations {
		oldValue := ""
		newValue := ""

		// Safely extract annotation values, handling nil maps
		if oldAnnotations != nil {
			oldValue = oldAnnotations[annotation]
		}
		if newAnnotations != nil {
			newValue = newAnnotations[annotation]
		}

		// If any relevant annotation value has changed, trigger reconciliation
		if oldValue != newValue {
			r.Log.V(2).Info("Relevant policy annotation changed - triggering reconciliation",
				"annotation", annotation,
				"old_value", oldValue,
				"new_value", newValue,
				"resource", newObj.GetName())
			return true
		}
	}

	// No relevant annotations changed - update can be skipped
	r.Log.V(3).Info("No relevant policy annotations changed - skipping reconciliation",
		"resource", newObj.GetName(),
		"checked_annotations", len(relevantAnnotations))
	return false
}
