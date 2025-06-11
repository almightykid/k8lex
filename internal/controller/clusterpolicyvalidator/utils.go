package clusterpolicyvalidator

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	clusterpolicyvalidatorv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyvalidator/v1alpha1"
	"github.com/go-logr/logr"
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
	// Iterate through all configured watched resource types
	for _, config := range r.WatchedResources {
		// Skip ClusterPolicyValidator resources to avoid self-validation loops
		if config.GVK.Kind == "ClusterPolicyValidator" &&
			config.GVK.Group == clusterpolicyvalidatorv1alpha1.GroupVersion.Group {
			continue
		}

		// Create a deep copy of the resource template to avoid modifying the original
		tempResource := config.Object.DeepCopyObject().(client.Object)
		tempResource.GetObjectKind().SetGroupVersionKind(config.GVK)

		// Attempt to retrieve the resource from the cluster
		if err := r.Get(ctx, req.NamespacedName, tempResource); err == nil {
			logger.V(2).Info("Found matching resource", "kind", config.GVK.Kind, "name", tempResource.GetName())
			return tempResource, config.GVK, nil
		}
	}

	// Increment metrics counter for resources not found or not watched
	errorTotal.WithLabelValues("resource_not_found_or_not_watched", "unknown").Inc()
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
