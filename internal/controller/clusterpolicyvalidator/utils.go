package clusterpolicyvalidator

import (
	"context"
	"fmt"
	"reflect"
	"strings"

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
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		annotations := resource.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		if len(violations) > 0 {
			annotations[PolicyViolationAnnotation] = "true"
			// Optionally, store details of the violation
			annotations[ViolationDetailsAnnotation] = fmt.Sprintf("%v", violations)
		} else {
			delete(annotations, PolicyViolationAnnotation)
			delete(annotations, ViolationDetailsAnnotation)
			delete(annotations, "k8lex.io/clusterpolicyupdater")
		}
		resource.SetAnnotations(annotations)
		if err := r.Update(ctx, resource); err != nil {
			if apierrors.IsConflict(err) {
				logger.Info("Conflict updating resource annotations, retrying", "attempt", i+1, "name", resource.GetName(), "namespace", resource.GetNamespace())
				// Reload the latest version and retry
				if errGet := r.Get(ctx, client.ObjectKey{Namespace: resource.GetNamespace(), Name: resource.GetName()}, resource); errGet != nil {
					logger.Error(errGet, "Failed to reload resource after conflict", "name", resource.GetName(), "namespace", resource.GetNamespace())
					return errGet
				}
				continue
			}
			logger.Error(err, "Failed to update resource annotations", "name", resource.GetName(), "namespace", resource.GetNamespace())
			return err
		}
		logger.V(1).Info("Updated resource annotations", "name", resource.GetName(), "namespace", resource.GetNamespace())
		return nil
	}
	return fmt.Errorf("Failed to update resource annotations after %d retries due to conflicts", maxRetries)
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
