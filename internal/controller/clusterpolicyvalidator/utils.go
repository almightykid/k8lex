package clusterpolicyvalidator

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	clusterpolicyvalidatorv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyvalidator/v1alpha1"
	"github.com/go-logr/logr"
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
	logger.V(2).Info("Searching for resource in dynamic GVKs",
		"namespacedName", req.NamespacedName,
		"dynamic_gvks_count", len(r.DynamicGVKs))

	// Iterate through all configured watched resource types
	for gvk := range r.DynamicGVKs {
		// Skip ClusterPolicyValidator resources to avoid self-validation loops
		if gvk.Kind == "ClusterPolicyValidator" &&
			gvk.Group == clusterpolicyvalidatorv1alpha1.GroupVersion.Group {
			logger.V(3).Info("Skipping ClusterPolicyValidator GVK to avoid self-validation", "gvk", gvk)
			continue
		}

		logger.V(3).Info("Trying to find resource as GVK",
			"gvk", gvk,
			"namespacedName", req.NamespacedName)

		// Create object for this GVK using the scheme
		obj, err := r.Scheme.New(gvk)
		if err != nil {
			logger.V(3).Info("Failed to create object for GVK", "gvk", gvk, "error", err)
			continue
		}

		// Ensure the object implements client.Object
		clientObj, ok := obj.(client.Object)
		if !ok {
			logger.V(3).Info("Object does not implement client.Object", "gvk", gvk)
			continue
		}

		// Set the GVK on the object (important for some operations)
		clientObj.GetObjectKind().SetGroupVersionKind(gvk)

		// Attempt to retrieve the resource from the cluster
		if err := r.Get(ctx, req.NamespacedName, clientObj); err == nil {
			logger.V(2).Info("Found matching resource",
				"kind", gvk.Kind,
				"name", clientObj.GetName(),
				"namespace", clientObj.GetNamespace(),
				"gvk", gvk)
			return clientObj, gvk, nil
		} else if !apierrors.IsNotFound(err) {
			// Real error (not just NotFound) - log and potentially return error
			logger.V(3).Info("Error getting resource as GVK", "gvk", gvk, "error", err)
			// For connectivity issues, we might want to return the error
			// But for now, we'll continue trying other GVKs
			continue
		} else {
			logger.V(3).Info("Resource not found as GVK", "gvk", gvk)
		}
	}

	logger.V(2).Info("Resource not found in any dynamic GVKs",
		"namespacedName", req.NamespacedName,
		"searched_gvks", len(r.DynamicGVKs))

	// Increment metrics counter for resources not found or not watched
	errorTotal.WithLabelValues("resource_not_found_or_not_watched", "unknown").Inc()

	// Return nil if not found in any GVK (this is expected for resources we don't watch)
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
	// Get existing annotations or create new map if none exist
	annotations := resource.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}

	if len(violations) > 0 {
		// Mark resource as having policy violations
		annotations[PolicyViolationAnnotation] = "true"

		// Build detailed violation information for each policy violation
		var details []string
		for _, v := range violations {
			detail := fmt.Sprintf("Policy: %s, Rule: %s, Severity: %s, Message: %s",
				v.PolicyName, v.RuleName, v.Severity, v.ErrorMessage)
			details = append(details, detail)
		}
		// Combine all violation details into a single annotation value
		annotations[ViolationDetailsAnnotation] = strings.Join(details, "; ")
	} else {
		// No violations found - remove violation annotations to clean up the resource
		delete(annotations, PolicyViolationAnnotation)
		delete(annotations, ViolationDetailsAnnotation)
	}

	// Apply the updated annotations to the resource
	resource.SetAnnotations(annotations)

	// Persist the annotation changes to the Kubernetes cluster
	if err := r.Update(ctx, resource); err != nil {
		logger.Error(err, "Failed to update resource annotations",
			"name", resource.GetName(),
			"namespace", resource.GetNamespace())
		errorTotal.WithLabelValues("failed_update_resource_annotations", resource.GetKind()).Inc()
		return err
	}

	return nil
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
	// Get current annotations, return early if none exist
	annotations := resource.GetAnnotations()
	if annotations == nil {
		return
	}

	// Check if violation annotations are present before attempting removal
	if _, exists := annotations[PolicyViolationAnnotation]; !exists {
		return
	}

	// Remove both violation-related annotations
	delete(annotations, PolicyViolationAnnotation)
	delete(annotations, ViolationDetailsAnnotation)
	resource.SetAnnotations(annotations)

	// Persist the annotation changes to the Kubernetes cluster
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
		// Track emergency bypasses separately in metrics for audit purposes
		policyBypassTotal.WithLabelValues("emergency", resource.GetObjectKind().GroupVersionKind().Kind).Inc()
		return true
	}

	// Check for regular policy bypass annotation
	if bypass, exists := annotations[PolicyBypassAnnotation]; exists && bypass == "true" {
		r.Log.Info("Policy bypass detected",
			"resource", resource.GetName(),
			"namespace", resource.GetNamespace())
		// Track regular bypasses in metrics
		policyBypassTotal.WithLabelValues("regular", resource.GetObjectKind().GroupVersionKind().Kind).Inc()
		return true
	}

	// No bypass annotations found or they're not set to "true"
	return false
}
