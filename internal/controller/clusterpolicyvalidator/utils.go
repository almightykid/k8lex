package clusterpolicyvalidator

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GVK cache for performance optimization - avoids iterating through all resource types
var (
	gvkCache      = sync.Map{} // map[string]schema.GroupVersionKind
	supportedGVKs = []schema.GroupVersionKind{
		{Group: "apps", Version: "v1", Kind: "Deployment"},
		{Group: "apps", Version: "v1", Kind: "StatefulSet"},
		{Group: "apps", Version: "v1", Kind: "ReplicaSet"},
		{Group: "apps", Version: "v1", Kind: "DaemonSet"},
		{Group: "batch", Version: "v1", Kind: "Job"},
		{Group: "batch", Version: "v1", Kind: "CronJob"},
	}
)

// createTypedObject creates a typed client.Object from a GVK for efficient resource queries
func createTypedObjectFromGVK(gvk schema.GroupVersionKind) client.Object {
	switch gvk {
	case schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}:
		return &appsv1.Deployment{}
	case schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "StatefulSet"}:
		return &appsv1.StatefulSet{}
	case schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "ReplicaSet"}:
		return &appsv1.ReplicaSet{}
	case schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "DaemonSet"}:
		return &appsv1.DaemonSet{}
	case schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "Job"}:
		return &batchv1.Job{}
	case schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "CronJob"}:
		return &batchv1.CronJob{}
	default:
		return nil
	}
}

// findResourceOptimized uses dynamic GVK discovery and caching to efficiently locate Kubernetes resources
// This replaces the inefficient iteration through all resource types with a targeted approach
func (r *ClusterPolicyValidatorReconciler) findResourceOptimized(ctx context.Context, req ctrl.Request, logger logr.Logger) (client.Object, schema.GroupVersionKind, error) {
	// Try to get GVK from cache first (namespace+name as key for resources that exist)
	cacheKey := fmt.Sprintf("%s/%s", req.Namespace, req.Name)
	if cachedGVK, exists := gvkCache.Load(cacheKey); exists {
		gvk := cachedGVK.(schema.GroupVersionKind)
		obj := createTypedObjectFromGVK(gvk)
		if obj != nil {
			err := r.Get(ctx, req.NamespacedName, obj)
			if err == nil {
				logger.V(3).Info("Resource found using cached GVK",
					"gvk", gvk, "cache_key", cacheKey)
				return obj, gvk, nil
			}
			// If resource not found, remove from cache
			if apierrors.IsNotFound(err) {
				gvkCache.Delete(cacheKey)
				logger.V(3).Info("Resource deleted, removing from GVK cache",
					"cache_key", cacheKey, "gvk", gvk)
			}
		}
	}

	// Cache miss or resource deleted - try supported GVKs directly
	for _, gvk := range supportedGVKs {
		obj := createTypedObjectFromGVK(gvk)
		if obj == nil {
			continue
		}

		err := r.Get(ctx, req.NamespacedName, obj)
		if err == nil {
			// Cache the successful GVK for future lookups
			gvkCache.Store(cacheKey, gvk)
			logger.V(2).Info("Resource found and cached",
				"gvk", gvk, "cache_key", cacheKey)
			return obj, gvk, nil
		}

		// Only log non-NotFound errors
		if !apierrors.IsNotFound(err) {
			logger.V(1).Info("Error checking resource type",
				"gvk", gvk, "error", err)
		}
	}

	// Resource not found in any of our supported types
	logger.V(2).Info("Resource not found in any supported resource types",
		"namespace", req.Namespace, "name", req.Name)
	return nil, schema.GroupVersionKind{}, nil
}

// clearGVKCache removes a specific entry from the GVK cache
// This is useful when resources are deleted or when testing
func clearGVKCacheEntry(namespace, name string) {
	cacheKey := fmt.Sprintf("%s/%s", namespace, name)
	gvkCache.Delete(cacheKey)
}

// clearAllGVKCache clears the entire GVK cache
// This can be useful for cleanup or when the supported resource types change
func clearAllGVKCache() {
	gvkCache.Range(func(key, value interface{}) bool {
		gvkCache.Delete(key)
		return true
	})
}

// getGVKCacheStats returns statistics about the GVK cache for monitoring
func getGVKCacheStats() (int, []string) {
	count := 0
	var keys []string
	gvkCache.Range(func(key, value interface{}) bool {
		count++
		keys = append(keys, key.(string))
		return true
	})
	return count, keys
}

// findResource attempts to find a Kubernetes resource across all watched resource types
// configured in the reconciler. It iterates through the WatchedResources configuration
// and tries to retrieve the resource specified in the reconcile request.
func (r *ClusterPolicyValidatorReconciler) findResource(ctx context.Context, req ctrl.Request, logger logr.Logger) (client.Object, schema.GroupVersionKind, error) {
	resourceTypes := []struct {
		obj client.Object
		gvk schema.GroupVersionKind
	}{
		{&appsv1.Deployment{}, schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}},
		{&appsv1.StatefulSet{}, schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "StatefulSet"}},
		{&appsv1.ReplicaSet{}, schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "ReplicaSet"}},
		{&appsv1.DaemonSet{}, schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "DaemonSet"}},
		{&batchv1.Job{}, schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "Job"}},
		{&batchv1.CronJob{}, schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "CronJob"}},
	}

	for _, rt := range resourceTypes {
		obj := rt.obj.DeepCopyObject().(client.Object)
		err := r.Get(ctx, req.NamespacedName, obj)
		if err == nil {
			return obj, rt.gvk, nil
		}
	}

	return nil, schema.GroupVersionKind{}, nil
}

// convertToUnstructured converts a typed Kubernetes resource object to an unstructured
// format, which allows for generic manipulation of resource fields without knowing
// the specific Go struct type at compile time.
func (r *ClusterPolicyValidatorReconciler) convertToUnstructured(resource client.Object, gvk schema.GroupVersionKind) (*unstructured.Unstructured, error) {
	// Convert the typed resource to a map[string]interface{} representation
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(resource)
	if err != nil {
		return nil, fmt.Errorf("failed to convert resource to unstructured: %w", err)
	}

	// Create unstructured object and set the appropriate GVK
	result := &unstructured.Unstructured{Object: unstructuredObj}
	result.SetGroupVersionKind(gvk)
	return result, nil
}

// getKindFromObject extracts the Kubernetes resource Kind from a client.Object.
// It first attempts to get the Kind from the object's GroupVersionKind, and if
// that's not available, it uses reflection to determine the type name.

func (r *ClusterPolicyValidatorReconciler) getKindFromObject(obj client.Object) string {
	// Primary method: Try to get Kind from the object's GroupVersionKind
	if gvk := obj.GetObjectKind().GroupVersionKind(); gvk.Kind != "" {
		return gvk.Kind
	}

	// Fallback method: Use Go reflection to determine the type name
	objType := reflect.TypeOf(obj)
	if objType == nil {
		return "Unknown"
	}

	// Dereference pointer types to get the underlying struct type
	if objType.Kind() == reflect.Ptr {
		objType = objType.Elem()
	}

	// Extract the type name from reflection
	typeName := objType.Name()

	// Map common Kubernetes resource type names to their standard Kind values
	// This ensures consistency with Kubernetes API conventions
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
		// For unknown types, return the reflection-derived type name
		return typeName
	}
}

// updateViolationAnnotations adds or updates annotations on a Kubernetes resource
// to indicate policy violations. This provides visibility into policy compliance
// directly on the resource object and enables monitoring and alerting.

func (r *ClusterPolicyValidatorReconciler) updateViolationAnnotations(
	ctx context.Context,
	resource *unstructured.Unstructured,
	violations []ValidationResult,
	logger logr.Logger,
) error {
	return r.updateAnnotationsWithRetry(ctx, resource, func(annotations map[string]string) error {
		if len(violations) > 0 {
			annotations[PolicyViolationAnnotation] = "true"
			// Store violation details as proper JSON for safe serialization
			if violationData, err := serializeViolations(violations); err == nil {
				annotations[ViolationDetailsAnnotation] = violationData
			} else {
				logger.Error(err, "Failed to serialize violation details", "violations_count", len(violations))
				annotations[ViolationDetailsAnnotation] = fmt.Sprintf("error: failed to serialize %d violations", len(violations))
			}
		} else {
			delete(annotations, PolicyViolationAnnotation)
			delete(annotations, ViolationDetailsAnnotation)
			delete(annotations, "k8lex.io/clusterpolicyupdater")
		}
		return nil
	}, logger)
}

// updateAnnotationsWithRetry implements robust retry logic for annotation updates
// This reduces race conditions by using optimistic locking with exponential backoff
func (r *ClusterPolicyValidatorReconciler) updateAnnotationsWithRetry(
	ctx context.Context,
	resource *unstructured.Unstructured,
	updateFunc func(map[string]string) error,
	logger logr.Logger,
) error {
	maxRetries := MaxAnnotationRetries
	baseDelay := 100 * time.Millisecond

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Get the latest version of the resource to avoid race conditions
		latestResource := &unstructured.Unstructured{}
		latestResource.SetGroupVersionKind(resource.GroupVersionKind())

		if err := r.Get(ctx, client.ObjectKey{
			Namespace: resource.GetNamespace(),
			Name:      resource.GetName(),
		}, latestResource); err != nil {
			if apierrors.IsNotFound(err) {
				logger.V(1).Info("Resource not found during annotation update",
					"name", resource.GetName(),
					"namespace", resource.GetNamespace())
				return nil // Resource was deleted, nothing to update
			}
			return createSecurityError(
				ErrorCodeRaceCondition,
				"Failed to get latest resource version",
				err,
			)
		}

		// Work with a copy to avoid modifying the original
		annotations := make(map[string]string)
		if existing := latestResource.GetAnnotations(); existing != nil {
			for k, v := range existing {
				annotations[k] = v
			}
		}

		// Apply the update function
		if err := updateFunc(annotations); err != nil {
			return fmt.Errorf("annotation update function failed: %w", err)
		}

		// Set annotations and attempt update
		latestResource.SetAnnotations(annotations)

		if err := r.Update(ctx, latestResource); err != nil {
			if apierrors.IsConflict(err) {
				// Exponential backoff for retries
				delay := time.Duration(1<<attempt) * baseDelay
				logger.V(2).Info("Conflict updating resource annotations, retrying with backoff",
					"attempt", attempt+1,
					"maxRetries", maxRetries,
					"delay", delay,
					"name", resource.GetName(),
					"namespace", resource.GetNamespace())

				// Sleep with exponential backoff
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(delay):
					// Continue to next retry
				}
				continue
			}
			// Non-conflict error, fail immediately
			return createSecurityError(
				ErrorCodeRaceCondition,
				"Failed to update resource annotations",
				err,
			)
		}

		// Success! Update the original resource with latest version
		resource.SetResourceVersion(latestResource.GetResourceVersion())
		resource.SetAnnotations(latestResource.GetAnnotations())

		logger.V(1).Info("Successfully updated resource annotations",
			"name", resource.GetName(),
			"namespace", resource.GetNamespace(),
			"attempts", attempt+1)
		return nil
	}

	return createSecurityError(
		ErrorCodeRaceCondition,
		fmt.Sprintf("Failed to update resource annotations after %d retries due to conflicts", maxRetries),
		nil,
	)
}

// updateResourceWithRetry implements robust retry logic for resource updates
// This is specifically for updating entire resources, not just annotations
func (r *ClusterPolicyValidatorReconciler) updateResourceWithRetry(
	ctx context.Context,
	resource *unstructured.Unstructured,
	logger logr.Logger,
) error {
	maxRetries := MaxAnnotationRetries
	baseDelay := 100 * time.Millisecond

	for attempt := 0; attempt < maxRetries; attempt++ {
		if err := r.Update(ctx, resource); err != nil {
			if apierrors.IsConflict(err) {
				// Get the latest version and merge our changes
				latestResource := &unstructured.Unstructured{}
				latestResource.SetGroupVersionKind(resource.GroupVersionKind())

				if errGet := r.Get(ctx, client.ObjectKey{
					Namespace: resource.GetNamespace(),
					Name:      resource.GetName(),
				}, latestResource); errGet != nil {
					if apierrors.IsNotFound(errGet) {
						logger.V(1).Info("Resource not found during update retry",
							"name", resource.GetName(),
							"namespace", resource.GetNamespace())
						return nil // Resource was deleted
					}
					return createSecurityError(
						ErrorCodeRaceCondition,
						"Failed to get latest resource version for update retry",
						errGet,
					)
				}

				// Merge our changes (annotations, spec.replicas, etc.) to the latest version
				// For this specific use case, we mainly care about preserving our changes
				latestResource.SetAnnotations(resource.GetAnnotations())

				// If we're updating spec.replicas, preserve that too
				if replicas, found, err := unstructured.NestedInt64(resource.Object, "spec", "replicas"); found && err == nil {
					if err := unstructured.SetNestedField(latestResource.Object, replicas, "spec", "replicas"); err != nil {
						logger.Error(err, "Failed to set replicas in latest resource version")
						return createSecurityError(
							ErrorCodeRaceCondition,
							"Failed to merge replicas during update retry",
							err,
						)
					}
				}

				// Update resource with latest version for next attempt
				resource = latestResource

				// Exponential backoff
				delay := time.Duration(1<<attempt) * baseDelay
				logger.V(2).Info("Resource update conflict, retrying with backoff",
					"attempt", attempt+1,
					"maxRetries", maxRetries,
					"delay", delay,
					"kind", resource.GetKind(),
					"name", resource.GetName(),
					"namespace", resource.GetNamespace())

				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(delay):
					// Continue to next retry
				}
				continue
			}

			// Non-conflict error, fail immediately
			return createSecurityError(
				ErrorCodeRaceCondition,
				"Failed to update resource (non-conflict error)",
				err,
			)
		}

		// Success
		logger.V(1).Info("Successfully updated resource",
			"kind", resource.GetKind(),
			"name", resource.GetName(),
			"namespace", resource.GetNamespace(),
			"attempts", attempt+1)
		return nil
	}

	return createSecurityError(
		ErrorCodeRaceCondition,
		fmt.Sprintf("Failed to update resource after %d retries due to conflicts", maxRetries),
		nil,
	)
}

// clearViolationAnnotations removes policy violation annotations from a Kubernetes
// resource. This is typically called when a resource becomes compliant with all
// policies or when the resource is no longer subject to policy validation.
// The function performs a safe cleanup by checking for annotation existence before
// attempting removal, avoiding unnecessary API calls.

func (r *ClusterPolicyValidatorReconciler) clearViolationAnnotations(
	ctx context.Context,
	resource *unstructured.Unstructured,
	logger logr.Logger,
) {
	annotations := resource.GetAnnotations()
	if annotations == nil {
		return
	}
	if _, exists := annotations[PolicyViolationAnnotation]; !exists {
		return
	}
	original := make(map[string]string, len(annotations))
	for k, v := range annotations {
		original[k] = v
	}
	delete(annotations, PolicyViolationAnnotation)
	delete(annotations, ViolationDetailsAnnotation)
	delete(annotations, "k8lex.io/clusterpolicyupdater")
	changed := false
	if len(annotations) != len(original) {
		changed = true
	} else {
		for k, v := range annotations {
			if original[k] != v {
				changed = true
				break
			}
		}
	}
	if changed {
		resource.SetAnnotations(annotations)
		if err := r.Update(ctx, resource); err != nil {
			logger.Error(err, "Failed to clear violation annotations",
				"name", resource.GetName(),
				"namespace", resource.GetNamespace())
		} else {
			logger.V(1).Info("Cleared violation annotations",
				"name", resource.GetName(),
				"namespace", resource.GetNamespace())
		}
	}
}

// formatErrorMessage creates a user-friendly error message by substituting template
// placeholders with actual resource information. This enables policy authors to
// create contextual error messages that reference specific resource attributes.
func (r *ClusterPolicyValidatorReconciler) formatErrorMessage(template string, resource *unstructured.Unstructured) string {
	// Provide default message if no template specified
	if template == "" {
		return "Resource violates policy"
	}

	// Start with the template and perform placeholder substitutions
	message := template
	message = strings.ReplaceAll(message, "{{ .metadata.name }}", resource.GetName())
	message = strings.ReplaceAll(message, "{{ .metadata.namespace }}", resource.GetNamespace())

	// Handle Kind substitution with fallback for unknown kinds
	kind := resource.GetKind()
	if kind == "" {
		kind = "Unknown"
	}
	message = strings.ReplaceAll(message, "{{ .kind }}", kind)

	return message
}

// shouldBypassPolicies determines whether a Kubernetes resource should skip policy
// validation based on special annotations. This provides escape mechanisms for
// emergency situations or specific operational needs.
//
// The function supports two types of bypass annotations:
//   - EmergencyBypassAnnotation: For critical situations requiring immediate deployment
//   - PolicyBypassAnnotation: For regular operational bypasses
//
// Emergency bypasses take precedence over regular bypasses and are tracked separately
// in metrics for audit and monitoring purposes.
func (r *ClusterPolicyValidatorReconciler) shouldBypassPolicies(resource client.Object) bool {
	// Safety check for nil resource
	if resource == nil {
		return false
	}

	// Get resource annotations, return false if none exist
	annotations := resource.GetAnnotations()
	if annotations == nil {
		return false
	}

	// Check for emergency bypass annotation - highest priority
	if bypass, exists := annotations[EmergencyBypassAnnotation]; exists && bypass == "true" {
		r.Log.Info("Emergency policy bypass detected",
			"resource", resource.GetName(),
			"namespace", resource.GetNamespace())
		return true
	}

	// Check for regular policy bypass annotation
	if bypass, exists := annotations[PolicyBypassAnnotation]; exists && bypass == "true" {
		r.Log.Info("Policy bypass detected",
			"resource", resource.GetName(),
			"namespace", resource.GetNamespace())
		return true
	}

	// No bypass annotations found or they're not set to "true"
	return false
}

// serializeViolations safely converts a slice of ValidationResult to JSON string
// This function provides proper serialization for storing violation details in annotations
// and prevents the unsafe use of fmt.Sprintf("%v", violations) which can produce unpredictable output
func serializeViolations(violations []ValidationResult) (string, error) {
	if len(violations) == 0 {
		return "", nil
	}

	// Create a summary structure for annotation storage (keep it concise)
	type ViolationSummary struct {
		Count      int                `json:"count"`
		Violations []ValidationResult `json:"violations,omitempty"`
		Timestamp  string             `json:"timestamp,omitempty"`
	}

	summary := ViolationSummary{
		Count:      len(violations),
		Violations: violations,
	}

	data, err := json.Marshal(summary)
	if err != nil {
		return "", fmt.Errorf("failed to marshal violation summary: %w", err)
	}

	return string(data), nil
}

// Security utility functions

// sanitizeLogValue truncates and sanitizes values for safe logging
// This prevents accidental exposure of sensitive information in logs
func sanitizeLogValue(value interface{}) string {
	if value == nil {
		return "<nil>"
	}

	str := fmt.Sprintf("%v", value)

	// Truncate long values to prevent log flooding
	if len(str) > MaxLogValueLength {
		return str[:MaxLogValueLength] + "...[truncated]"
	}

	// Additional sanitization rules can be added here
	// For example, masking patterns that look like secrets

	return str
}

// sanitizeLogMap sanitizes all values in a map for safe logging
func sanitizeLogMap(m map[string]interface{}) map[string]string {
	if m == nil {
		return nil
	}

	result := make(map[string]string, len(m))
	for k, v := range m {
		result[sanitizeLogValue(k)] = sanitizeLogValue(v)
	}
	return result
}

// createSecurityError creates a structured security error with proper error code
func createSecurityError(code, message string, cause error) error {
	return SecurityError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}
