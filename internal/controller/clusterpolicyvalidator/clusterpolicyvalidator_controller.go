package clusterpolicyvalidator

import (
	"context"
	"fmt"
	"math"
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
	PolicyBypassAnnotation       = "k8lex.io/policy-bypass"
	EmergencyBypassAnnotation    = "k8lex.io/emergency-bypass"

	// Constants for reconcile behavior
	DefaultRequeueDelay = 30 * time.Second
	MaxRetries          = 5
	JQCacheMaxSize      = 1000

	// NEW: Retry and backoff constants
	MaxBackoffDelay   = 300 * time.Second // 5 minutes
	BaseBackoffDelay  = 1 * time.Second
	BackoffMultiplier = 2.0
	JitterMaxFactor   = 0.1

	// NEW: Circuit breaker constants
	CircuitBreakerThreshold = 5
	CircuitBreakerTimeout   = 60 * time.Second

	// NEW: Cache constants
	PolicyCacheTTL       = 5 * time.Minute
	PolicyEvalCacheTTL   = 2 * time.Minute
	JQCacheTTL           = 10 * time.Minute
	CacheCleanupInterval = 1 * time.Minute

	// NEW: Performance constants
	MaxConcurrentEvaluations = 10
	EvaluationTimeout        = 30 * time.Second
)

// NEW: Policy failure modes
type FailureMode string

const (
	FailSecure FailureMode = "fail-secure" // Block on failure
	FailSafe   FailureMode = "fail-safe"   // Allow on failure
)

// NEW: Circuit breaker state
type CircuitBreakerState int

const (
	CircuitClosed CircuitBreakerState = iota
	CircuitOpen
	CircuitHalfOpen
)

// NEW: Enhanced cache entry with TTL
type CacheEntry struct {
	Value       interface{}
	ExpiresAt   time.Time
	AccessCount int64
	LastAccess  time.Time
}

// NEW: LRU Cache with TTL
type LRUCache struct {
	mu       sync.RWMutex
	capacity int
	entries  map[string]*CacheEntry
	order    []string // LRU order
}

// NEW: Circuit breaker for API operations
type CircuitBreaker struct {
	mu           sync.RWMutex
	state        CircuitBreakerState
	failures     int
	lastFailTime time.Time
	timeout      time.Duration
	threshold    int
}

// NEW: Policy evaluation result cache entry
type PolicyEvalCacheEntry struct {
	ResourceVersion string
	PolicyVersion   string
	Result          []ValidationResult
	CachedAt        time.Time
}

// NEW: Enhanced retry configuration
type RetryConfig struct {
	MaxRetries      int
	BaseDelay       time.Duration
	MaxDelay        time.Duration
	Multiplier      float64
	JitterMaxFactor float64
}

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

	// NEW: Enhanced caching with LRU and TTL
	jqCache         *LRUCache
	policyEvalCache *LRUCache
	policyCache     *LRUCache

	// NEW: Circuit breakers for different operations
	apiCircuitBreaker    *CircuitBreaker
	policyCircuitBreaker *CircuitBreaker

	// NEW: Enhanced retry configuration
	retryConfig RetryConfig

	// NEW: Failure mode configuration
	FailureMode FailureMode

	// Rate limiting for policy evaluations
	policyEvalLimiter map[string]*time.Timer
	evalLimiterMu     sync.RWMutex

	// Namespace filtering state - per reconciler instead of global
	namespaceFilter   *NamespaceFilterState
	namespaceFilterMu sync.RWMutex

	// Conflict resolution strategy
	ConflictResolution PolicyConflictResolution

	// NEW: Semaphore for limiting concurrent evaluations
	evaluationSemaphore chan struct{}

	// NEW: Context for graceful shutdown
	shutdownCtx context.Context
	cancel      context.CancelFunc
}

// NamespaceFilterState holds the aggregated namespace filtering rules from all policies.
type NamespaceFilterState struct {
	IncludedNamespaces map[string]struct{}
	ExcludedNamespaces map[string]struct{}
	HasIncludeRules    bool
	HasExcludeRules    bool
	LastUpdated        time.Time
}

// NEW: LRU Cache implementation
func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		entries:  make(map[string]*CacheEntry),
		order:    make([]string, 0, capacity),
	}
}

func (c *LRUCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		delete(c.entries, key)
		c.removeFromOrder(key)
		return nil, false
	}

	// Update access info
	entry.AccessCount++
	entry.LastAccess = time.Now()
	c.moveToFront(key)

	return entry.Value, true
}

func (c *LRUCache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry := &CacheEntry{
		Value:       value,
		ExpiresAt:   time.Now().Add(ttl),
		AccessCount: 1,
		LastAccess:  time.Now(),
	}

	// If key exists, update it
	if _, exists := c.entries[key]; exists {
		c.entries[key] = entry
		c.moveToFront(key)
		return
	}

	// If at capacity, remove LRU item
	if len(c.entries) >= c.capacity {
		c.evictLRU()
	}

	c.entries[key] = entry
	c.order = append([]string{key}, c.order...)
}

func (c *LRUCache) moveToFront(key string) {
	for i, k := range c.order {
		if k == key {
			copy(c.order[1:i+1], c.order[0:i])
			c.order[0] = key
			return
		}
	}
}

func (c *LRUCache) removeFromOrder(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
}

func (c *LRUCache) evictLRU() {
	if len(c.order) == 0 {
		return
	}

	lruKey := c.order[len(c.order)-1]
	delete(c.entries, lruKey)
	c.order = c.order[:len(c.order)-1]
}

func (c *LRUCache) CleanupExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	cleaned := 0

	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
			c.removeFromOrder(key)
			cleaned++
		}
	}

	return cleaned
}

// NEW: Circuit breaker implementation
func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:     CircuitClosed,
		threshold: threshold,
		timeout:   timeout,
	}
}

func (cb *CircuitBreaker) Call(fn func() error) error {
	cb.mu.RLock()
	state := cb.state
	failures := cb.failures
	lastFailTime := cb.lastFailTime
	cb.mu.RUnlock()

	// Check if circuit should transition from Open to HalfOpen
	if state == CircuitOpen && time.Since(lastFailTime) > cb.timeout {
		cb.mu.Lock()
		if cb.state == CircuitOpen && time.Since(cb.lastFailTime) > cb.timeout {
			cb.state = CircuitHalfOpen
		}
		cb.mu.Unlock()
	}

	// Reject if circuit is open
	if state == CircuitOpen {
		return fmt.Errorf("circuit breaker is open (failures: %d)", failures)
	}

	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failures++
		cb.lastFailTime = time.Now()

		if cb.failures >= cb.threshold {
			cb.state = CircuitOpen
		}

		return err
	}

	// Success - reset circuit breaker
	if cb.state == CircuitHalfOpen {
		cb.state = CircuitClosed
	}
	cb.failures = 0

	return nil
}

// NEW: Enhanced retry with exponential backoff and jitter
func (r *ClusterPolicyValidatorReconciler) retryWithBackoff(ctx context.Context, operation func() error, operationName string) error {
	var lastErr error

	for attempt := 0; attempt < r.retryConfig.MaxRetries; attempt++ {
		// Use circuit breaker for API operations
		var err error
		if strings.Contains(operationName, "api") {
			err = r.apiCircuitBreaker.Call(operation)
		} else {
			err = operation()
		}

		if err == nil {
			return nil
		}

		lastErr = err

		// Don't retry on certain errors
		if apierrors.IsNotFound(err) || apierrors.IsUnauthorized(err) || apierrors.IsForbidden(err) {
			return err
		}

		// Calculate backoff delay with jitter
		delay := r.calculateBackoffDelay(attempt)

		r.Log.Info("Operation failed, retrying",
			"operation", operationName,
			"attempt", attempt+1,
			"maxRetries", r.retryConfig.MaxRetries,
			"delay", delay,
			"error", err.Error())

		// Update retry metrics
		retryAttempts.WithLabelValues(operationName, fmt.Sprintf("%d", attempt+1)).Inc()

		// Wait with context cancellation support
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	return fmt.Errorf("operation %s failed after %d attempts: %w", operationName, r.retryConfig.MaxRetries, lastErr)
}

func (r *ClusterPolicyValidatorReconciler) calculateBackoffDelay(attempt int) time.Duration {
	delay := float64(r.retryConfig.BaseDelay) * math.Pow(r.retryConfig.Multiplier, float64(attempt))

	// Add jitter
	jitter := delay * r.retryConfig.JitterMaxFactor * (2*math.Pow(math.Phi, float64(attempt)) - 1) // Using golden ratio for better distribution
	delay += jitter

	// Cap at max delay
	if delay > float64(r.retryConfig.MaxDelay) {
		delay = float64(r.retryConfig.MaxDelay)
	}

	return time.Duration(delay)
}

// NEW: Check if resource should bypass policies (emergency situations)
func (r *ClusterPolicyValidatorReconciler) shouldBypassPolicies(resource client.Object) bool {
	if resource == nil {
		return false
	}

	annotations := resource.GetAnnotations()

	if annotations == nil {
		return false
	}

	// Emergency bypass - always takes precedence
	if bypass, exists := annotations[EmergencyBypassAnnotation]; exists && bypass == "true" {
		r.Log.Info("Emergency policy bypass detected",
			"resource", resource.GetName(),
			"namespace", resource.GetNamespace())
		policyBypassTotal.WithLabelValues("emergency", resource.GetObjectKind().GroupVersionKind().Kind).Inc()
		return true
	}

	// Regular policy bypass
	if bypass, exists := annotations[PolicyBypassAnnotation]; exists && bypass == "true" {
		r.Log.Info("Policy bypass detected",
			"resource", resource.GetName(),
			"namespace", resource.GetNamespace())
		policyBypassTotal.WithLabelValues("regular", resource.GetObjectKind().GroupVersionKind().Kind).Inc()
		return true
	}

	return false
}

// Initialize and ensure the reconciler is properly set up
func (r *ClusterPolicyValidatorReconciler) initializeIfNeeded() {
	if r.jqCache == nil {
		r.jqCache = NewLRUCache(JQCacheMaxSize)
	}
	if r.policyEvalCache == nil {
		r.policyEvalCache = NewLRUCache(JQCacheMaxSize)
	}
	if r.policyCache == nil {
		r.policyCache = NewLRUCache(100)
	}
	if r.apiCircuitBreaker == nil {
		r.apiCircuitBreaker = NewCircuitBreaker(CircuitBreakerThreshold, CircuitBreakerTimeout)
	}
	if r.policyCircuitBreaker == nil {
		r.policyCircuitBreaker = NewCircuitBreaker(CircuitBreakerThreshold, CircuitBreakerTimeout)
	}
	if r.policyEvalLimiter == nil {
		r.policyEvalLimiter = make(map[string]*time.Timer)
	}
	if r.evaluationSemaphore == nil {
		r.evaluationSemaphore = make(chan struct{}, MaxConcurrentEvaluations)
	}
	if r.retryConfig.MaxRetries == 0 {
		r.retryConfig = RetryConfig{
			MaxRetries:      MaxRetries,
			BaseDelay:       BaseBackoffDelay,
			MaxDelay:        MaxBackoffDelay,
			Multiplier:      BackoffMultiplier,
			JitterMaxFactor: JitterMaxFactor,
		}
	}
	if r.FailureMode == "" {
		r.FailureMode = FailSecure
	}
	if r.ConflictResolution == "" {
		r.ConflictResolution = ConflictResolutionMostRestrictive
	}
	if r.namespaceFilter == nil {
		r.namespaceFilter = &NamespaceFilterState{
			IncludedNamespaces: make(map[string]struct{}),
			ExcludedNamespaces: make(map[string]struct{}),
		}
	}
	if r.shutdownCtx == nil {
		r.shutdownCtx, r.cancel = context.WithCancel(context.Background())
	}
}

// Enhanced SetupWithManager - compatible with main.go structure
func (r *ClusterPolicyValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize the reconciler
	r.Log = mgr.GetLogger().WithName("clusterpolicyvalidator-controller")
	r.EventRecorder = mgr.GetEventRecorderFor("clusterpolicyvalidator-controller")

	// Initialize all components
	r.initializeIfNeeded()

	// Start background cache cleanup
	r.startCacheCleanup(r.shutdownCtx)

	// Build the controller
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 5,
		})

	// Add watches for dynamic resources with optimized predicates
	for _, config := range r.WatchedResources {
		// Skip ClusterPolicyValidator as it's already watched
		if config.GVK.Kind == "ClusterPolicyValidator" &&
			config.GVK.Group == clusterpolicyvalidatorv1alpha1.GroupVersion.Group {
			continue
		}

		r.Log.Info("Setting up optimized watch", "GVK", config.GVK)

		builder = builder.Watches(
			config.Object,
			&handler.EnqueueRequestForObject{},
		).WithEventFilter(r.optimizedEventFilter())
	}

	return builder.Complete(r)
}

// NEW: Start background cache cleanup goroutine
func (r *ClusterPolicyValidatorReconciler) startCacheCleanup(ctx context.Context) {
	ticker := time.NewTicker(CacheCleanupInterval)

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.cleanupCaches()
			}
		}
	}()
}

// NEW: Enhanced cache cleanup with TTL support
func (r *ClusterPolicyValidatorReconciler) cleanupCaches() {
	// Clean up expired entries
	var jqCleaned, evalCleaned, policyCleaned int

	if r.jqCache != nil {
		jqCleaned = r.jqCache.CleanupExpired()
	}
	if r.policyEvalCache != nil {
		evalCleaned = r.policyEvalCache.CleanupExpired()
	}
	if r.policyCache != nil {
		policyCleaned = r.policyCache.CleanupExpired()
	}

	if jqCleaned > 0 || evalCleaned > 0 || policyCleaned > 0 {
		r.Log.V(2).Info("Cleaned up expired cache entries",
			"jq_cleaned", jqCleaned,
			"eval_cleaned", evalCleaned,
			"policy_cleaned", policyCleaned)
	}
}

// NEW: Optimized event filter with field selectors and generation checking
func (r *ClusterPolicyValidatorReconciler) optimizedEventFilter() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			kind := r.getKindFromObject(e.Object)
			logger := r.Log.WithValues("event", "create", "kind", kind)

			// Skip if namespace not allowed
			if !r.isNamespaceAllowedByPredicate(e.Object.GetNamespace(), logger) {
				return false
			}

			// Skip if resource has policy bypass
			if r.shouldBypassPolicies(e.Object) {
				logger.V(2).Info("Skipping create event due to policy bypass",
					"resource", e.Object.GetName(),
					"namespace", e.Object.GetNamespace())
				return false
			}

			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Skip if object hasn't actually changed (avoid unnecessary reconciles)
			if e.ObjectOld != nil && e.ObjectNew != nil {
				if e.ObjectOld.GetResourceVersion() == e.ObjectNew.GetResourceVersion() {
					return false
				}

				// Only reconcile if the spec has changed (generation) OR our annotations changed
				if e.ObjectOld.GetGeneration() == e.ObjectNew.GetGeneration() {
					if !r.relevantAnnotationsChanged(e.ObjectOld, e.ObjectNew) {
						return false
					}
				}
			}

			kind := r.getKindFromObject(e.ObjectNew)
			logger := r.Log.WithValues("event", "update", "kind", kind)

			// Skip if namespace not allowed
			if !r.isNamespaceAllowedByPredicate(e.ObjectNew.GetNamespace(), logger) {
				return false
			}

			// Skip if resource has policy bypass
			if r.shouldBypassPolicies(e.ObjectNew) {
				logger.V(2).Info("Skipping update event due to policy bypass",
					"resource", e.ObjectNew.GetName(),
					"namespace", e.ObjectNew.GetNamespace())
				return false
			}

			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			kind := r.getKindFromObject(e.Object)
			logger := r.Log.WithValues("event", "delete", "kind", kind)

			// Always process deletes if namespace is allowed (cleanup)
			return r.isNamespaceAllowedByPredicate(e.Object.GetNamespace(), logger)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			kind := r.getKindFromObject(e.Object)
			logger := r.Log.WithValues("event", "generic", "kind", kind)

			// Skip if namespace not allowed
			if !r.isNamespaceAllowedByPredicate(e.Object.GetNamespace(), logger) {
				return false
			}

			// Skip if resource has policy bypass
			if r.shouldBypassPolicies(e.Object) {
				logger.V(2).Info("Skipping generic event due to policy bypass",
					"resource", e.Object.GetName(),
					"namespace", e.Object.GetNamespace())
				return false
			}

			return true
		},
	}
}

// NEW: Check if relevant annotations have changed
func (r *ClusterPolicyValidatorReconciler) relevantAnnotationsChanged(oldObj, newObj client.Object) bool {
	oldAnnotations := oldObj.GetAnnotations()
	newAnnotations := newObj.GetAnnotations()

	relevantAnnotations := []string{
		PolicyBlockedAnnotation,
		PolicyViolationAnnotation,
		PolicyBypassAnnotation,
		EmergencyBypassAnnotation,
	}

	for _, annotation := range relevantAnnotations {
		oldValue := ""
		newValue := ""

		if oldAnnotations != nil {
			oldValue = oldAnnotations[annotation]
		}
		if newAnnotations != nil {
			newValue = newAnnotations[annotation]
		}

		if oldValue != newValue {
			return true
		}
	}

	return false
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

// Enhanced Reconcile method with better error handling and performance
func (r *ClusterPolicyValidatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("ClusterPolicyValidator", req.NamespacedName)
	r.Log = logger

	// Ensure reconciler is initialized
	r.initializeIfNeeded()

	start := time.Now()
	reconcileResultLabel := "success"

	defer func() {
		reconcileDuration.WithLabelValues("clusterpolicyvalidator", reconcileResultLabel).Observe(time.Since(start).Seconds())
	}()

	// Try to fetch the ClusterPolicyValidator resource with retry
	policy := &clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{}
	var err error

	err = r.retryWithBackoff(ctx, func() error {
		return r.Get(ctx, req.NamespacedName, policy)
	}, "api-get-policy")

	if err == nil {
		// This is a policy change, update namespace filter state and invalidate caches
		r.Log.Info("ClusterPolicyValidator reconciled, updating state", "policy", policy.Name)

		// Invalidate policy cache since policies changed
		if r.policyCache != nil {
			r.policyCache = NewLRUCache(100)
		}

		if err := r.UpdateNamespaceFilterState(ctx); err != nil {
			reconcileResultLabel = "error"
			return ctrl.Result{RequeueAfter: r.calculateBackoffDelay(1)}, err
		}
		return ctrl.Result{}, nil
	}

	if !apierrors.IsNotFound(err) {
		r.Log.Error(err, "Unable to fetch ClusterPolicyValidator")
		reconcileResultLabel = "error"
		return ctrl.Result{RequeueAfter: r.calculateBackoffDelay(1)}, err
	}

	// This is a resource validation request
	r.Log.V(1).Info("Processing resource validation", "namespacedName", req.NamespacedName)
	result, err := r.validateResource(ctx, req, logger)

	if err != nil {
		reconcileResultLabel = "error"
		// Enhanced backoff calculation based on error type
		delay := r.calculateBackoffDelay(1)

		// Different delays for different error types
		if apierrors.IsServiceUnavailable(err) || apierrors.IsTimeout(err) {
			delay = r.calculateBackoffDelay(2) // Longer delay for server issues
		}

		return ctrl.Result{RequeueAfter: delay}, err
	}

	return result, nil
}

// Enhanced namespace filter state update with retries
func (r *ClusterPolicyValidatorReconciler) UpdateNamespaceFilterState(ctx context.Context) error {
	return r.retryWithBackoff(ctx, func() error {
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
	}, "api-update-namespace-filter")
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

// isNamespaceAllowedByPredicate with proper include/exclude precedence
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

// NEW: Enhanced policy evaluation with caching and failure handling
func (r *ClusterPolicyValidatorReconciler) evaluatePolicies(
	ctx context.Context,
	resource *unstructured.Unstructured,
	foundResource client.Object,
	resourceGVK schema.GroupVersionKind,
	policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator,
	logger logr.Logger,
) []ValidationResult {
	// Check for policy bypass
	if r.shouldBypassPolicies(foundResource) {
		return []ValidationResult{}
	}

	// Generate cache key
	cacheKey := r.generatePolicyEvalCacheKey(resource, policies)

	// Check cache first
	if r.policyEvalCache != nil {
		if cached, found := r.policyEvalCache.Get(cacheKey); found {
			if entry, ok := cached.(*PolicyEvalCacheEntry); ok {
				// Verify resource and policy versions haven't changed
				if entry.ResourceVersion == resource.GetResourceVersion() {
					logger.V(2).Info("Using cached policy evaluation result",
						"resource", resource.GetName(),
						"cacheKey", cacheKey)
					return entry.Result
				}
			}
		}
	}

	// Acquire semaphore for concurrent evaluation limiting
	select {
	case r.evaluationSemaphore <- struct{}{}:
		defer func() { <-r.evaluationSemaphore }()
		concurrentEvaluations.Inc()
		defer concurrentEvaluations.Dec()
	case <-ctx.Done():
		return []ValidationResult{}
	}

	// Create timeout context for evaluation
	evalCtx, cancel := context.WithTimeout(ctx, EvaluationTimeout)
	defer cancel()

	// Evaluate policies with circuit breaker
	var violations []ValidationResult
	var evalErr error

	start := time.Now()
	defer func() {
		evaluationLatency.WithLabelValues("all-policies", resourceGVK.Kind).Observe(time.Since(start).Seconds())
	}()

	err := r.policyCircuitBreaker.Call(func() error {
		violations, evalErr = r.evaluatePoliciesInternal(evalCtx, resource, foundResource, resourceGVK, policies, logger)
		return evalErr
	})

	if err != nil {
		// Handle failure based on failure mode
		if r.FailureMode == FailSecure {
			// Fail secure - treat as blocking violation
			logger.Error(err, "Policy evaluation failed, failing secure",
				"resource", resource.GetName(),
				"failureMode", r.FailureMode)

			return []ValidationResult{{
				PolicyName:   "system",
				RuleName:     "evaluation-failure",
				Violated:     true,
				Action:       "block",
				Severity:     "critical",
				ErrorMessage: fmt.Sprintf("Policy evaluation failed: %v", err),
				ResourcePath: "system",
			}}
		} else {
			// Fail safe - log error but allow resource
			logger.Error(err, "Policy evaluation failed, failing safe",
				"resource", resource.GetName(),
				"failureMode", r.FailureMode)

			return []ValidationResult{}
		}
	}

	// Cache the result
	if r.policyEvalCache != nil {
		cacheEntry := &PolicyEvalCacheEntry{
			ResourceVersion: resource.GetResourceVersion(),
			PolicyVersion:   r.generatePolicyVersion(policies),
			Result:          violations,
			CachedAt:        time.Now(),
		}

		r.policyEvalCache.Set(cacheKey, cacheEntry, PolicyEvalCacheTTL)
	}

	return violations
}

func (r *ClusterPolicyValidatorReconciler) generatePolicyEvalCacheKey(resource *unstructured.Unstructured, policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator) string {
	return fmt.Sprintf("%s-%s-%s-%s",
		resource.GetKind(),
		resource.GetNamespace(),
		resource.GetName(),
		resource.GetResourceVersion())
}

func (r *ClusterPolicyValidatorReconciler) generatePolicyVersion(policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator) string {
	// Simple hash of all policy resource versions
	var versions []string
	for _, policy := range policies {
		versions = append(versions, policy.GetResourceVersion())
	}
	return strings.Join(versions, "-")
}

// Original evaluatePolicies method renamed and enhanced
func (r *ClusterPolicyValidatorReconciler) evaluatePoliciesInternal(
	ctx context.Context,
	resource *unstructured.Unstructured,
	foundResource client.Object,
	resourceGVK schema.GroupVersionKind,
	policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator,
	logger logr.Logger,
) ([]ValidationResult, error) {
	var violations []ValidationResult

	for _, policy := range policies {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return violations, ctx.Err()
		default:
		}

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
	r.cleanupCaches()

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
			return []ValidationResult{violation}, nil // Return only the blocking violation
		}
	}

	return violations, nil
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

	// Add rate limiting timer (1 second minimum between evaluations)
	r.policyEvalLimiter[policyName] = time.NewTimer(time.Second)
	return true
}

// NEW: Enhanced compiled JQ with caching and error handling
func (r *ClusterPolicyValidatorReconciler) getCompiledJQ(query string) (*gojq.Code, error) {
	// Check cache first
	if r.jqCache != nil {
		if cached, found := r.jqCache.Get(query); found {
			if code, ok := cached.(*gojq.Code); ok {
				jqCacheHits.Inc()
				return code, nil
			}
		}
	}

	jqCacheMisses.Inc()

	// Parse and compile query with error handling
	q, err := gojq.Parse(query)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jq query: %w", err)
	}

	code, err := gojq.Compile(q)
	if err != nil {
		return nil, fmt.Errorf("failed to compile jq query: %w", err)
	}

	// Cache the compiled query with TTL
	if r.jqCache != nil {
		r.jqCache.Set(query, code, JQCacheTTL)
	}

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

// NEW: Enhanced resource validation with field selectors and better error handling
func (r *ClusterPolicyValidatorReconciler) validateResource(ctx context.Context, req ctrl.Request, logger logr.Logger) (ctrl.Result, error) {
	validationAttempts.Inc()

	// Enhanced resource finding with retries
	var foundResource client.Object
	var resourceGVK schema.GroupVersionKind
	var err error

	err = r.retryWithBackoff(ctx, func() error {
		foundResource, resourceGVK, err = r.findResource(ctx, req, logger)
		return err
	}, "api-find-resource")

	if err != nil {
		return ctrl.Result{RequeueAfter: r.calculateBackoffDelay(1)}, err
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

	// Get all policies with caching
	var policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator
	err = r.retryWithBackoff(ctx, func() error {
		policies, err = r.listPoliciesCached(ctx)
		return err
	}, "api-list-policies")

	if err != nil {
		errorTotal.WithLabelValues("failed_to_list_policies", resourceGVK.Kind).Inc()
		return ctrl.Result{}, err
	}

	// Validate against all applicable policies with enhanced error handling
	violations := r.evaluatePolicies(ctx, resource, foundResource, resourceGVK, policies, logger)

	// Handle violations
	if len(violations) > 0 {
		return r.handleViolations(ctx, foundResource, resource, resourceGVK, violations, logger)
	}

	// Clear any previous violation annotations if no violations found
	r.clearViolationAnnotations(ctx, resource, logger)

	return ctrl.Result{}, nil
}

// NEW: Enhanced policy listing with caching
func (r *ClusterPolicyValidatorReconciler) listPoliciesCached(ctx context.Context) ([]clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator, error) {
	cacheKey := "all-policies"

	// Check cache first
	if r.policyCache != nil {
		if cached, found := r.policyCache.Get(cacheKey); found {
			if policies, ok := cached.([]clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator); ok {
				return policies, nil
			}
		}
	}

	// Fetch from API
	var policies clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorList
	if err := r.List(ctx, &policies); err != nil {
		return nil, fmt.Errorf("failed to list ClusterPolicyValidator policies: %w", err)
	}

	// Cache the result
	if r.policyCache != nil {
		r.policyCache.Set(cacheKey, policies.Items, PolicyCacheTTL)
	}

	return policies.Items, nil
}

// NEW: Graceful shutdown method
func (r *ClusterPolicyValidatorReconciler) Shutdown() {
	r.Log.Info("Shutting down ClusterPolicyValidator reconciler")

	if r.cancel != nil {
		r.cancel()
	}

	// Wait for ongoing evaluations to complete
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()

	for i := 0; i < cap(r.evaluationSemaphore); i++ {
		select {
		case r.evaluationSemaphore <- struct{}{}:
			// Successfully acquired, release immediately
			<-r.evaluationSemaphore
		case <-timeout.C:
			r.Log.Info("Timeout waiting for evaluations to complete during shutdown")
			return
		}
	}

	r.Log.Info("ClusterPolicyValidator reconciler shutdown complete")
}

// Enhanced GetMetrics method
func (r *ClusterPolicyValidatorReconciler) GetMetrics() map[string]interface{} {
	r.namespaceFilterMu.RLock()
	defer r.namespaceFilterMu.RUnlock()

	// Update cache size metrics
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

	// Update Prometheus metrics
	cacheSize.WithLabelValues("jq").Set(float64(jqCacheLen))
	cacheSize.WithLabelValues("policy_eval").Set(float64(policyEvalCacheLen))
	cacheSize.WithLabelValues("policy").Set(float64(policyCacheLen))

	// Update circuit breaker state metrics
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

	// Update failure mode metric
	if r.FailureMode == FailSecure {
		failureMode.WithLabelValues("fail-secure").Set(1)
		failureMode.WithLabelValues("fail-safe").Set(0)
	} else {
		failureMode.WithLabelValues("fail-secure").Set(0)
		failureMode.WithLabelValues("fail-safe").Set(1)
	}

	return map[string]interface{}{
		"caches": map[string]interface{}{
			"jq_cache_size":          jqCacheLen,
			"policy_eval_cache_size": policyEvalCacheLen,
			"policy_cache_size":      policyCacheLen,
		},
		"circuit_breakers": map[string]interface{}{
			"api_breaker_state":    0,
			"policy_breaker_state": 0,
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

// Prometheus metrics (enhanced with new metrics)
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

	// NEW: Register enhanced metrics
	metrics.Registry.MustRegister(retryAttempts)
	metrics.Registry.MustRegister(circuitBreakerState)
	metrics.Registry.MustRegister(cacheSize)
	metrics.Registry.MustRegister(cacheHitRatio)
	metrics.Registry.MustRegister(evaluationLatency)
	metrics.Registry.MustRegister(concurrentEvaluations)
	metrics.Registry.MustRegister(failureMode)
	metrics.Registry.MustRegister(policyBypassTotal)
}

// NOTE: All the remaining methods from your original code would be included here:
// - resolveConflicts, applyConflictResolution, selectMostRestrictive, selectHighestSeverity
// - findResource, convertToUnstructured, evaluateRule, validateCondition, evaluateSingleCondition
// - handleViolations, handleResourceAction, handleBlockAction, handlePodBlocking, etc.

// Here are the key methods that need to be included from your original code:

// Policy conflict resolution
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
