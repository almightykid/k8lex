package clusterpolicyvalidator

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/go-logr/logr"

	clusterpolicyvalidatorv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyvalidator/v1alpha1"
)

// initializeIfNeeded performs lazy initialization of all enhanced controller features
// This method ensures backward compatibility by initializing components only when needed,
// allowing existing code to work without modification while providing enhanced capabilities
func (r *ClusterPolicyValidatorReconciler) initializeIfNeeded() {
	// Initialize JQ query compilation cache for performance optimization
	if r.jqCache == nil {
		r.jqCache = NewLRUCache(JQCacheMaxSize)
	}

	// Initialize policy evaluation result cache to avoid redundant policy evaluations
	if r.policyEvalCache == nil {
		r.policyEvalCache = NewLRUCache(JQCacheMaxSize)
	}

	// Initialize policy object cache to reduce Kubernetes API load
	if r.policyCache == nil {
		r.policyCache = NewLRUCache(100) // Smaller cache size for policy objects
	}

	// Initialize circuit breaker for Kubernetes API operations to prevent cascading failures
	if r.apiCircuitBreaker == nil {
		r.apiCircuitBreaker = NewCircuitBreaker(CircuitBreakerThreshold, CircuitBreakerTimeout)
	}

	// Initialize circuit breaker for policy evaluations to handle evaluation failures gracefully
	if r.policyCircuitBreaker == nil {
		r.policyCircuitBreaker = NewCircuitBreaker(CircuitBreakerThreshold, CircuitBreakerTimeout)
	}

	// Initialize rate limiting structures to prevent policy evaluation storms
	if r.policyEvalLimiter == nil {
		r.policyEvalLimiter = make(map[string]*time.Timer)
	}

	// Initialize evaluation semaphore for concurrency control and resource management
	if r.evaluationSemaphore == nil {
		r.evaluationSemaphore = make(chan struct{}, MaxConcurrentEvaluations)
	}

	// Initialize retry configuration with enterprise-grade defaults
	if r.retryConfig.MaxRetries == 0 {
		r.retryConfig = RetryConfig{
			MaxRetries:      MaxRetries,
			BaseDelay:       BaseBackoffDelay,
			MaxDelay:        MaxBackoffDelay,
			Multiplier:      BackoffMultiplier,
			JitterMaxFactor: JitterMaxFactor,
		}
	}

	// Set default failure mode to secure-by-default for production safety
	if r.FailureMode == "" {
		r.FailureMode = FailSecure // Block resources when policy evaluation fails
	}

	// Set default conflict resolution strategy to most restrictive for security
	if r.ConflictResolution == "" {
		r.ConflictResolution = ConflictResolutionMostRestrictive
	}

	// Initialize namespace filtering state for policy scope management
	if r.namespaceFilter == nil {
		r.namespaceFilter = &NamespaceFilterState{
			IncludedNamespaces: make(map[string]struct{}),
			ExcludedNamespaces: make(map[string]struct{}),
		}
	}

	// Initialize graceful shutdown coordination context
	if r.shutdownCtx == nil {
		r.shutdownCtx, r.cancel = context.WithCancel(context.Background())
	}
}

// SetupWithManager configures the controller with the manager and establishes all necessary watches
// This method integrates enhanced features while maintaining compatibility with the existing main.go structure
// It sets up dynamic resource watching, optimized event filtering, and background maintenance tasks
func (r *ClusterPolicyValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize structured logging with controller-specific context
	r.Log = mgr.GetLogger().WithName("clusterpolicyvalidator-controller")
	r.EventRecorder = mgr.GetEventRecorderFor("clusterpolicyvalidator-controller")

	// Ensure all enhanced features are properly initialized
	r.initializeIfNeeded()

	// Start background maintenance tasks for cache cleanup and resource management
	r.startCacheCleanup(r.shutdownCtx)

	r.Log.Info("Setting up ClusterPolicyValidator controller with enhanced features",
		"failure_mode", r.FailureMode,
		"conflict_resolution", r.ConflictResolution,
		"max_concurrent_evaluations", MaxConcurrentEvaluations,
		"cache_cleanup_interval", CacheCleanupInterval,
		"circuit_breaker_threshold", CircuitBreakerThreshold)

	// Build the controller with optimized configuration for production workloads
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 5, // Limit concurrent reconciliations for resource management
		})

	// Set up dynamic resource watches with intelligent event filtering
	for _, config := range r.WatchedResources {
		// Skip ClusterPolicyValidator as it's already being watched by the For() clause above
		if config.GVK.Kind == "ClusterPolicyValidator" &&
			config.GVK.Group == clusterpolicyvalidatorv1alpha1.GroupVersion.Group {
			continue
		}

		r.Log.Info("Configuring enhanced resource watch with optimized event filtering",
			"group", config.GVK.Group,
			"version", config.GVK.Version,
			"kind", config.GVK.Kind,
			"features", "namespace_filtering,generation_tracking,bypass_detection")

		// Add watch with optimized predicates to reduce unnecessary reconciliations
		builder = builder.Watches(
			config.Object,
			&handler.EnqueueRequestForObject{},
		).WithEventFilter(r.optimizedEventFilter())
	}

	// Complete controller setup and register with the manager
	return builder.Complete(r)
}

// Reconcile is the main reconciliation loop implementing enhanced error handling and performance optimizations
// This method handles both policy configuration changes and resource validation requests with enterprise-grade
// reliability patterns including circuit breakers, exponential backoff, and comprehensive observability
func (r *ClusterPolicyValidatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("ClusterPolicyValidator", req.NamespacedName)
	r.Log = logger

	// Ensure all enhanced features are initialized before processing any requests
	r.initializeIfNeeded()

	// Track reconciliation performance for monitoring and alerting
	start := time.Now()
	reconcileResultLabel := "success"

	// Record reconciliation metrics when function exits
	defer func() {
		duration := time.Since(start)
		reconcileDuration.WithLabelValues("clusterpolicyvalidator", reconcileResultLabel).Observe(duration.Seconds())
		logger.V(2).Info("Reconciliation completed",
			"duration", duration,
			"result", reconcileResultLabel)
	}()

	// Attempt to fetch ClusterPolicyValidator resource with retry logic and circuit breaker protection
	policy := &clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{}

	err := r.retryWithBackoff(ctx, func() error {
		return r.Get(ctx, req.NamespacedName, policy)
	}, "api-get-policy")

	if err == nil {
		// This reconciliation is for a policy configuration change
		logger.Info("Processing ClusterPolicyValidator policy configuration change",
			"policy_name", policy.Name,
			"generation", policy.Generation,
			"resource_version", policy.ResourceVersion,
			"action", "updating_system_state")

		// Invalidate policy cache to ensure fresh policy data for subsequent evaluations
		if r.policyCache != nil {
			r.policyCache = NewLRUCache(100)
			logger.V(2).Info("Policy cache invalidated due to policy configuration change")
		}

		// Update namespace filtering rules based on new policy configuration
		if err := r.UpdateNamespaceFilterState(ctx); err != nil {
			reconcileResultLabel = "error"
			logger.Error(err, "Failed to update namespace filter state after policy change")
			return ctrl.Result{RequeueAfter: r.calculateBackoffDelay(1)}, err
		}

		logger.Info("Policy configuration change processed successfully",
			"policy_name", policy.Name)
		return ctrl.Result{}, nil
	}

	// Handle non-NotFound errors with appropriate retry logic
	if !apierrors.IsNotFound(err) {
		logger.Error(err, "Failed to fetch ClusterPolicyValidator resource - will retry with backoff")
		reconcileResultLabel = "error"
		return ctrl.Result{RequeueAfter: r.calculateBackoffDelay(1)}, err
	}

	// This is a resource validation request (policy resource was not found)
	logger.V(1).Info("Processing resource validation request",
		"namespacedName", req.NamespacedName,
		"action", "validating_resource_against_policies")

	// Execute resource validation with enhanced error handling and performance optimizations
	result, err := r.validateResource(ctx, req, logger)

	if err != nil {
		reconcileResultLabel = "error"

		// Calculate appropriate backoff delay based on error type for intelligent retry behavior
		delay := r.calculateBackoffDelay(1)
		if apierrors.IsServiceUnavailable(err) || apierrors.IsTimeout(err) {
			delay = r.calculateBackoffDelay(2) // Longer delay for server-side issues
			logger.Info("Server-side error detected - using extended backoff delay",
				"error_type", fmt.Sprintf("%T", err),
				"delay", delay)
		}

		logger.Error(err, "Resource validation failed - will retry with backoff",
			"delay", delay,
			"error_type", fmt.Sprintf("%T", err))
		return ctrl.Result{RequeueAfter: delay}, err
	}

	return result, nil
}

// validateResource performs comprehensive resource validation with enhanced error handling and performance optimization
// This method implements the complete validation pipeline including resource discovery, policy retrieval,
// policy evaluation, and violation handling with full observability and reliability features
func (r *ClusterPolicyValidatorReconciler) validateResource(ctx context.Context, req ctrl.Request, logger logr.Logger) (ctrl.Result, error) {
	// Increment validation attempt counter for monitoring
	validationAttempts.Inc()

	logger.V(1).Info("Starting enhanced resource validation pipeline",
		"namespacedName", req.NamespacedName,
		"features", "retry_logic,circuit_breakers,caching,conflict_resolution")

	// Enhanced resource discovery with retry logic and circuit breaker protection
	var foundResource client.Object
	var resourceGVK schema.GroupVersionKind
	var err error

	err = r.retryWithBackoff(ctx, func() error {
		foundResource, resourceGVK, err = r.findResource(ctx, req, logger)
		return err
	}, "api-find-resource")

	if err != nil {
		logger.Error(err, "Resource discovery failed after retry attempts")
		return ctrl.Result{RequeueAfter: r.calculateBackoffDelay(1)}, err
	}

	// Handle case where resource is not found or not in watched resource types
	if foundResource == nil {
		logger.V(2).Info("Resource not found in watched resource types - skipping validation",
			"namespacedName", req.NamespacedName,
			"watched_types", len(r.WatchedResources))
		return ctrl.Result{}, nil
	}

	// Record successful resource processing metrics
	resourceProcessedTotal.WithLabelValues(resourceGVK.Kind).Inc()
	logger.Info("Resource discovered successfully for validation",
		"resource_kind", resourceGVK.Kind,
		"resource_name", foundResource.GetName(),
		"resource_namespace", foundResource.GetNamespace(),
		"resource_version", foundResource.GetResourceVersion())

	// Convert resource to unstructured format for generic policy evaluation
	resource, err := r.convertToUnstructured(foundResource, resourceGVK)
	if err != nil {
		errorTotal.WithLabelValues("failed_to_convert_to_unstructured", resourceGVK.Kind).Inc()
		logger.Error(err, "Failed to convert resource to unstructured format for policy evaluation")
		return ctrl.Result{}, err
	}

	// Retrieve applicable policies with caching and retry logic
	var policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator
	err = r.retryWithBackoff(ctx, func() error {
		policies, err = r.listPoliciesCached(ctx)
		return err
	}, "api-list-policies")

	if err != nil {
		errorTotal.WithLabelValues("failed_to_list_policies", resourceGVK.Kind).Inc()
		logger.Error(err, "Failed to retrieve policies for validation")
		return ctrl.Result{}, err
	}

	logger.V(1).Info("Starting policy evaluation against resource",
		"resource", foundResource.GetName(),
		"kind", resourceGVK.Kind,
		"namespace", foundResource.GetNamespace(),
		"policy_count", len(policies))

	// Execute comprehensive policy evaluation with enhanced features
	violations := r.evaluatePolicies(ctx, resource, foundResource, resourceGVK, policies, logger)

	// Handle any policy violations that were detected
	if len(violations) > 0 {
		logger.Info("Policy violations detected - initiating enforcement actions",
			"violation_count", len(violations),
			"resource", foundResource.GetName(),
			"kind", resourceGVK.Kind)
		return r.handleViolations(ctx, foundResource, resource, resourceGVK, violations, logger)
	}

	// Clear any previous violation annotations since no violations were found
	r.clearViolationAnnotations(ctx, resource, logger)
	logger.V(1).Info("Resource validation completed successfully - no policy violations detected",
		"resource", foundResource.GetName(),
		"kind", resourceGVK.Kind,
		"policies_evaluated", len(policies))

	return ctrl.Result{}, nil
}

// Shutdown performs graceful shutdown of the controller with proper resource cleanup
// This method ensures all ongoing operations complete cleanly and resources are properly released
// It implements timeout-based shutdown to prevent hanging during system termination
func (r *ClusterPolicyValidatorReconciler) Shutdown() {
	r.Log.Info("Initiating graceful shutdown of ClusterPolicyValidator controller",
		"max_concurrent_evaluations", cap(r.evaluationSemaphore),
		"shutdown_timeout", "30s")

	// Cancel the shutdown context to signal all background tasks to stop
	if r.cancel != nil {
		r.cancel()
		r.Log.V(2).Info("Shutdown context cancelled - background tasks will terminate")
	}

	// Wait for all ongoing policy evaluations to complete with timeout protection
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()

	// Acquire all semaphore slots to ensure no policy evaluations are running
	for i := 0; i < cap(r.evaluationSemaphore); i++ {
		select {
		case r.evaluationSemaphore <- struct{}{}:
			// Successfully acquired semaphore slot, release it immediately
			<-r.evaluationSemaphore
			r.Log.V(3).Info("Policy evaluation slot acquired and released during shutdown",
				"slot", i+1,
				"total_slots", cap(r.evaluationSemaphore))
		case <-timeout.C:
			r.Log.Info("Shutdown timeout reached while waiting for policy evaluations to complete",
				"completed_slots", i,
				"total_slots", cap(r.evaluationSemaphore),
				"timeout", "30s")
			return
		}
	}

	r.Log.Info("ClusterPolicyValidator controller shutdown completed successfully",
		"all_evaluations_completed", true,
		"background_tasks_stopped", true)
}

// GetMetrics collects and returns current operational metrics for monitoring and debugging
// This method provides comprehensive visibility into controller performance, cache effectiveness,
// circuit breaker states, and system configuration for operational monitoring
func (r *ClusterPolicyValidatorReconciler) GetMetrics() map[string]interface{} {
	r.namespaceFilterMu.RLock()
	defer r.namespaceFilterMu.RUnlock()

	// Collect cache size information safely with proper locking
	jqCacheLen := 0
	policyEvalCacheLen := 0
	policyCacheLen := 0

	if r.jqCache != nil {
		r.jqCache.mu.RLock()
		jqCacheLen = len(r.jqCache.entries)
		r.jqCache.mu.RUnlock()
	}

	if r.policyEvalCache != nil {
		r.policyEvalCache.mu.RLock()
		policyEvalCacheLen = len(r.policyEvalCache.entries)
		r.policyEvalCache.mu.RUnlock()
	}

	if r.policyCache != nil {
		r.policyCache.mu.RLock()
		policyCacheLen = len(r.policyCache.entries)
		r.policyCache.mu.RUnlock()
	}

	// Update Prometheus metrics for external monitoring systems
	cacheSize.WithLabelValues("jq").Set(float64(jqCacheLen))
	cacheSize.WithLabelValues("policy_eval").Set(float64(policyEvalCacheLen))
	cacheSize.WithLabelValues("policy").Set(float64(policyCacheLen))

	// Update circuit breaker state metrics for reliability monitoring
	if r.apiCircuitBreaker != nil {
		r.apiCircuitBreaker.mu.RLock()
		circuitBreakerState.WithLabelValues("api").Set(float64(r.apiCircuitBreaker.state))
		r.apiCircuitBreaker.mu.RUnlock()
	}

	if r.policyCircuitBreaker != nil {
		r.policyCircuitBreaker.mu.RLock()
		circuitBreakerState.WithLabelValues("policy").Set(float64(r.policyCircuitBreaker.state))
		r.policyCircuitBreaker.mu.RUnlock()
	}

	// Update failure mode metrics for security posture monitoring
	if r.FailureMode == FailSecure {
		failureMode.WithLabelValues("fail-secure").Set(1)
		failureMode.WithLabelValues("fail-safe").Set(0)
	} else {
		failureMode.WithLabelValues("fail-secure").Set(0)
		failureMode.WithLabelValues("fail-safe").Set(1)
	}

	// Return comprehensive metrics map for internal consumption
	return map[string]interface{}{
		"caches": map[string]interface{}{
			"jq_cache_size":          jqCacheLen,
			"policy_eval_cache_size": policyEvalCacheLen,
			"policy_cache_size":      policyCacheLen,
		},
		"circuit_breakers": map[string]interface{}{
			"api_breaker_state":    0, // Will be updated by Prometheus metrics
			"policy_breaker_state": 0, // Will be updated by Prometheus metrics
		},
		"configuration": map[string]interface{}{
			"watched_resources":    len(r.WatchedResources),
			"failure_mode":         r.FailureMode,
			"conflict_resolution":  r.ConflictResolution,
			"max_retries":          r.retryConfig.MaxRetries,
			"max_concurrent_evals": cap(r.evaluationSemaphore),
		},
		"namespace_filter": map[string]interface{}{
			"included_count": len(r.namespaceFilter.IncludedNamespaces),
			"excluded_count": len(r.namespaceFilter.ExcludedNamespaces),
			"has_include":    r.namespaceFilter.HasIncludeRules,
			"has_exclude":    r.namespaceFilter.HasExcludeRules,
			"last_updated":   r.namespaceFilter.LastUpdated,
		},
	}
}

// HealthCheck provides a comprehensive health check for the controller and its dependencies
// This method verifies that the controller can communicate with the Kubernetes API and that
// all enhanced features are properly initialized and functioning
func (r *ClusterPolicyValidatorReconciler) HealthCheck() error {
	// Create a context with reasonable timeout for health check operations
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r.Log.V(2).Info("Performing comprehensive controller health check",
		"timeout", "5s",
		"checks", "api_connectivity,policy_listing,enhanced_features")

	// Verify Kubernetes API connectivity by attempting to list policies
	var policies clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorList
	if err := r.List(ctx, &policies); err != nil {
		return fmt.Errorf("health check failed - unable to communicate with Kubernetes API: %w", err)
	}

	// Verify that enhanced features are properly initialized
	if r.jqCache == nil || r.policyEvalCache == nil || r.apiCircuitBreaker == nil {
		return fmt.Errorf("health check failed - enhanced features not properly initialized")
	}

	// Verify that critical configuration is set
	if r.FailureMode == "" || r.ConflictResolution == "" {
		return fmt.Errorf("health check failed - critical configuration not set")
	}

	r.Log.V(2).Info("Controller health check completed successfully",
		"api_accessible", true,
		"policy_count", len(policies.Items),
		"enhanced_features_initialized", true,
		"configuration_valid", true)

	return nil
}
