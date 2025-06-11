package clusterpolicyvalidator

import (
	"context"
	"fmt"
	"strings"
	"time"

	clusterpolicyvalidatorv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyvalidator/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// NewLRUCache creates a new Least Recently Used cache with the specified capacity
// The cache combines LRU eviction with TTL expiration for optimal memory management
// and data freshness guarantees
func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		entries:  make(map[string]*CacheEntry),
		order:    make([]string, 0, capacity),
	}
}

// Get retrieves a value from the cache, updating access tracking and checking expiration
// Returns the cached value and true if found and not expired, nil and false otherwise
// This method is thread-safe and automatically handles TTL expiration cleanup
func (c *LRUCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	// Check if the entry has expired and clean it up immediately
	if time.Now().After(entry.ExpiresAt) {
		delete(c.entries, key)
		c.removeFromOrder(key)
		return nil, false
	}

	// Update access tracking for LRU algorithm effectiveness
	entry.AccessCount++
	entry.LastAccess = time.Now()
	c.moveToFront(key)

	return entry.Value, true
}

// Set stores a value in the cache with the specified Time-To-Live duration
// If the cache is at capacity, the least recently used item will be evicted
// This method is thread-safe and handles both updates and new insertions
func (c *LRUCache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry := &CacheEntry{
		Value:       value,
		ExpiresAt:   time.Now().Add(ttl),
		AccessCount: 1,
		LastAccess:  time.Now(),
	}

	// If key already exists, update it and move to front of LRU order
	if _, exists := c.entries[key]; exists {
		c.entries[key] = entry
		c.moveToFront(key)
		return
	}

	// If at capacity, evict the least recently used item before insertion
	if len(c.entries) >= c.capacity {
		c.evictLRU()
	}

	// Add new entry at the front of the LRU order (most recently used)
	c.entries[key] = entry
	c.order = append([]string{key}, c.order...)
}

// moveToFront moves the specified key to the front of the LRU order using an optimized copy approach
// This method efficiently handles the common case of promoting recently accessed items
func (c *LRUCache) moveToFront(key string) {
	// Find the key position and shift elements efficiently
	for i, k := range c.order {
		if k == key {
			// Use copy to shift elements left, then place key at front
			copy(c.order[1:i+1], c.order[0:i])
			c.order[0] = key
			return
		}
	}
}

// removeFromOrder removes the specified key from the LRU order slice
// This is used during eviction and expiration cleanup operations
func (c *LRUCache) removeFromOrder(key string) {
	for i, k := range c.order {
		if k == key {
			// Remove element by combining slices before and after the target index
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
}

// evictLRU removes the least recently used item from the cache
// This method is called when the cache reaches capacity and needs to make room for new entries
func (c *LRUCache) evictLRU() {
	if len(c.order) == 0 {
		return // No entries to evict
	}

	// The last item in the order slice is the least recently used
	lruKey := c.order[len(c.order)-1]
	delete(c.entries, lruKey)
	c.order = c.order[:len(c.order)-1]
}

// CleanupExpired removes all expired entries from the cache in a single operation
// This method is designed for periodic cleanup tasks and returns the number of cleaned entries
// It performs a full scan of the cache, which is suitable for background maintenance
func (c *LRUCache) CleanupExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	cleaned := 0

	// Iterate through all entries and remove expired ones
	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
			c.removeFromOrder(key)
			cleaned++
		}
	}

	return cleaned
}

// startCacheCleanup begins a background goroutine that periodically cleans up expired cache entries
// This prevents memory leaks from expired entries and maintains cache performance over time
// The cleanup routine respects context cancellation for graceful shutdown
func (r *ClusterPolicyValidatorReconciler) startCacheCleanup(ctx context.Context) {
	ticker := time.NewTicker(CacheCleanupInterval)

	go func() {
		defer ticker.Stop()
		r.Log.V(2).Info("Started cache cleanup background task",
			"cleanup_interval", CacheCleanupInterval,
			"cache_types", "jq, policy_evaluation, policy_objects")

		for {
			select {
			case <-ctx.Done():
				r.Log.V(2).Info("Cache cleanup task stopping due to context cancellation")
				return
			case <-ticker.C:
				r.cleanupCaches()
			}
		}
	}()
}

// cleanupCaches performs cleanup operations on all cache types managed by the reconciler
// This method coordinates cleanup across JQ query cache, policy evaluation cache, and policy object cache
// It logs cleanup activity for monitoring and debugging purposes
func (r *ClusterPolicyValidatorReconciler) cleanupCaches() {
	var jqCleaned, evalCleaned, policyCleaned int

	// Clean up JQ query compilation cache
	if r.jqCache != nil {
		jqCleaned = r.jqCache.CleanupExpired()
	}

	// Clean up policy evaluation result cache
	if r.policyEvalCache != nil {
		evalCleaned = r.policyEvalCache.CleanupExpired()
	}

	// Clean up policy object cache
	if r.policyCache != nil {
		policyCleaned = r.policyCache.CleanupExpired()
	}

	// Log cleanup activity only if entries were actually cleaned
	if jqCleaned > 0 || evalCleaned > 0 || policyCleaned > 0 {
		r.Log.V(2).Info("Cache cleanup completed successfully",
			"jq_entries_cleaned", jqCleaned,
			"evaluation_entries_cleaned", evalCleaned,
			"policy_entries_cleaned", policyCleaned,
			"total_entries_cleaned", jqCleaned+evalCleaned+policyCleaned)
	}
}

// generatePolicyEvalCacheKey creates a unique cache key for policy evaluation results
// The key incorporates resource identity and version to ensure cache invalidation
// when either the resource or its content changes
func (r *ClusterPolicyValidatorReconciler) generatePolicyEvalCacheKey(resource *unstructured.Unstructured, policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator) string {
	return fmt.Sprintf("%s-%s-%s-%s",
		resource.GetKind(),            // Resource type for cache segmentation
		resource.GetNamespace(),       // Namespace for multi-tenancy support
		resource.GetName(),            // Resource name for uniqueness
		resource.GetResourceVersion()) // Version for cache invalidation
}

// generatePolicyVersion creates a composite version identifier from multiple policies
// This version string is used for cache invalidation when any policy in the set changes
// The approach uses resource versions which change whenever policy objects are modified
func (r *ClusterPolicyValidatorReconciler) generatePolicyVersion(policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator) string {
	var versions []string

	// Collect resource versions from all policies to create composite version
	for _, policy := range policies {
		versions = append(versions, policy.GetResourceVersion())
	}

	// Join versions with delimiter for uniqueness across policy combinations
	return strings.Join(versions, "-")
}

// listPoliciesCached retrieves all ClusterPolicyValidator policies with intelligent caching
// This method implements a cache-aside pattern: check cache first, then fetch from API if needed
// The caching significantly reduces Kubernetes API load during frequent policy evaluations
func (r *ClusterPolicyValidatorReconciler) listPoliciesCached(ctx context.Context) ([]clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator, error) {
	cacheKey := "all-policies"

	// Attempt to retrieve policies from cache first (cache-aside pattern)
	if r.policyCache != nil {
		if cached, found := r.policyCache.Get(cacheKey); found {
			if policies, ok := cached.([]clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator); ok {
				r.Log.V(3).Info("Retrieved policies from cache",
					"policy_count", len(policies),
					"cache_key", cacheKey)
				return policies, nil
			}
		}
	}

	// Cache miss - fetch policies from Kubernetes API
	var policies clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorList
	if err := r.List(ctx, &policies); err != nil {
		return nil, fmt.Errorf("failed to list ClusterPolicyValidator policies from Kubernetes API: %w", err)
	}

	r.Log.V(2).Info("Fetched policies from Kubernetes API",
		"policy_count", len(policies.Items),
		"cache_key", cacheKey)

	// Store the fetched policies in cache for subsequent requests
	if r.policyCache != nil {
		r.policyCache.Set(cacheKey, policies.Items, PolicyCacheTTL)
		r.Log.V(3).Info("Cached policy list for future requests",
			"ttl", PolicyCacheTTL,
			"policy_count", len(policies.Items))
	}

	return policies.Items, nil
}
