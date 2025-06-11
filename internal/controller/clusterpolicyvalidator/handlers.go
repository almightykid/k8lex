package clusterpolicyvalidator

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// handleViolations processes a list of policy violations for a given Kubernetes resource.
// It iterates through each violation, records relevant metrics, and executes the
// corresponding action (e.g., block, warn, audit). If a "block" action is encountered,
// processing stops immediately for that resource.
// Finally, it updates resource annotations with the violation details.
// Returns a `ctrl.Result` indicating if requeueing is needed and an error.
func (r *ClusterPolicyValidatorReconciler) handleViolations(
	ctx context.Context,
	foundResource client.Object, // The typed Kubernetes client.Object (e.g., *appsv1.Deployment).
	resource *unstructured.Unstructured, // The unstructured representation of the resource.
	resourceGVK schema.GroupVersionKind, // The GroupVersionKind of the resource.
	violations []ValidationResult, // A slice of policy violations detected for the resource.
	logger logr.Logger, // Logger for structured logging.
) (ctrl.Result, error) {
	// Iterate over each detected violation.
	for _, violation := range violations {
		// Record Prometheus metrics for policy violations and actions taken.
		policyViolations.WithLabelValues(violation.PolicyName, resourceGVK.Kind, violation.Severity).Inc()
		actionTakenTotal.WithLabelValues(violation.Action, resourceGVK.Kind, violation.Severity).Inc()

		// Execute the action defined by the policy (e.g., "block", "warn", "audit").
		if err := r.handleResourceAction(ctx, foundResource, resourceGVK.Kind, violation, logger); err != nil {
			// If an error occurs during action handling, requeue the reconciliation
			// after a default delay to retry the operation.
			logger.Error(err, "Failed to handle resource action for violation",
				"resource", foundResource.GetName(),
				"policy", violation.PolicyName,
				"action", violation.Action)
			return ctrl.Result{RequeueAfter: DefaultRequeueDelay}, err
		}

		// If the action taken was "block", stop processing further violations for this resource.
		// A blocking action is decisive, and subsequent actions are irrelevant as the resource is being prevented.
		if strings.ToLower(violation.Action) == "block" {
			logger.Info("Resource blocked due to policy violation; stopping further violation processing",
				"policy", violation.PolicyName,
				"rule", violation.RuleName,
				"resource", foundResource.GetName(),
				"kind", resourceGVK.Kind)
			return ctrl.Result{}, nil // Return an empty result, indicating no requeue is immediately needed.
		}
	}

	// After handling all (non-blocking) violations, update the resource's annotations
	// to reflect the presence and details of any violations. This provides visibility
	// into the resource's policy compliance state.
	return ctrl.Result{}, r.updateViolationAnnotations(ctx, resource, violations, logger)
}

// handleResourceAction dispatches the appropriate handler function based on the
// `Action` defined in the `ValidationResult`. This centralizes the logic for
// executing policy-defined responses to violations.
func (r *ClusterPolicyValidatorReconciler) handleResourceAction(
	ctx context.Context,
	resource client.Object, // The Kubernetes resource (e.g., Pod, Deployment) that violated the policy.
	kind string, // The Kind of the resource (e.g., "Pod", "Deployment").
	violation ValidationResult, // The details of the policy violation, including the action to take.
	logger logr.Logger, // Logger for structured logging.
) error {
	resourceName := resource.GetName()
	namespace := resource.GetNamespace()

	// Log the action being taken for visibility and auditing.
	logger.Info("Taking action for policy violation",
		"resource", resourceName,
		"namespace", namespace,
		"kind", kind,
		"policy", violation.PolicyName,
		"rule", violation.RuleName,
		"action", violation.Action,
		"severity", violation.Severity,
		"errorMessage", violation.ErrorMessage)

	// Use a switch statement to dispatch to the specific handler function for each action type.
	switch strings.ToLower(violation.Action) {
	case "block":
		return r.handleBlockAction(ctx, resource, kind, violation, logger)
	case "warn":
		return r.handleWarnAction(ctx, resource, violation, logger)
	case "audit":
		return r.handleAuditAction(ctx, resource, violation, logger)
	case "continue":
		// The "continue" action implies no active enforcement is required.
		// Simply log the event and return nil (no error, no further action).
		logger.V(1).Info("Policy action 'continue' detected, no enforcement action taken",
			"resource", resourceName, "policy", violation.PolicyName)
		return nil
	default:
		// Log an informational message if an unknown action type is encountered.
		// This suggests a misconfiguration in the ClusterPolicyValidator definition.
		logger.Info("Unknown action type for policy violation", "action", violation.Action,
			"resource", resourceName, "policy", violation.PolicyName)
		return nil
	}
}

// handleBlockAction serves as a dispatcher for blocking actions.
// It determines the specific blocking strategy based on the `kind` of the resource.
// This allows for different blocking behaviors for Pods, controller resources, and generic resources.
func (r *ClusterPolicyValidatorReconciler) handleBlockAction(
	ctx context.Context,
	resource client.Object, // The Kubernetes resource to block.
	kind string, // The Kind of the resource (e.g., "Pod", "Deployment").
	violation ValidationResult, // Details of the violation leading to blocking.
	logger logr.Logger, // Logger for structured logging.
) error {
	// Dispatch to specialized blocking functions based on resource Kind.
	switch kind {
	case "Pod":
		// Pods might need special handling if they are managed by a controller (e.g., Deployment).
		return r.handlePodBlocking(ctx, resource, violation, logger)
	case "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet":
		// Controller resources are typically scaled down to zero to prevent them from running.
		return r.handleControllerBlocking(ctx, resource, violation, logger)
	default:
		// For all other resource types, a generic deletion is applied.
		return r.handleGenericResourceBlocking(ctx, resource, violation, logger)
	}
}

// handlePodBlocking implements the blocking action for Pod resources.
// It checks if a Pod is managed by a controller (specifically ReplicaSet) and, if so,
// attempts to block the parent controller instead of directly deleting the Pod.
// For standalone Pods, it directly deletes them.
func (r *ClusterPolicyValidatorReconciler) handlePodBlocking(
	ctx context.Context,
	resource client.Object, // The Pod resource to block.
	violation ValidationResult, // Details of the violation.
	logger logr.Logger, // Logger for structured logging.
) error {
	// Check if the Pod has owner references, indicating it's managed by a controller.
	if ownerRefs := resource.GetOwnerReferences(); len(ownerRefs) > 0 {
		for _, ownerRef := range ownerRefs {
			// If the owner is a ReplicaSet, this Pod is likely part of a Deployment.
			// In such cases, we want to scale down the parent Deployment, not just delete the Pod,
			// as the Deployment would immediately re-create it.
			if ownerRef.Kind == "ReplicaSet" {
				logger.Info("Pod is managed by a ReplicaSet; attempting to handle parent Deployment instead",
					"pod", resource.GetName(),
					"namespace", resource.GetNamespace(),
					"replicaSet", ownerRef.Name)
				// Delegate to a helper function that finds and blocks the parent Deployment.
				return r.handleDeploymentViolation(ctx, resource.GetNamespace(), ownerRef.Name, violation, logger)
			}
			// Add checks for other controller types if needed (e.g., StatefulSet, DaemonSet directly).
		}
	}

	// If the Pod has no owner references, or no relevant owner was found, treat it as a standalone Pod.
	// Directly delete the standalone Pod.
	logger.Info("Deleting standalone Pod due to policy violation",
		"pod", resource.GetName(),
		"namespace", resource.GetNamespace(),
		"violation", violation.ErrorMessage)
	if err := r.Delete(ctx, resource); client.IgnoreNotFound(err) != nil {
		// Log and return error if deletion fails, ignoring "not found" errors which mean it's already gone.
		logger.Error(err, "Failed to delete standalone Pod", "pod", resource.GetName())
		errorTotal.WithLabelValues("failed_to_delete_pod", "Pod").Inc() // Metric for deletion failures.
		return err
	}

	// Record a Kubernetes event to signal the Pod's deletion due to policy violation.
	r.EventRecorder.Eventf(resource, corev1.EventTypeWarning, "PolicyViolation",
		"Pod %s deleted due to policy violation: %s", resource.GetName(), violation.ErrorMessage)

	return nil // Pod successfully deleted or was already gone.
}

// handleControllerBlocking implements the blocking action for controller-type resources
// such as Deployments, ReplicaSets, DaemonSets, and StatefulSets.
// The strategy is to scale these resources down to zero replicas and annotate them
// to indicate they are policy-blocked and store their original replica count.
func (r *ClusterPolicyValidatorReconciler) handleControllerBlocking(
	ctx context.Context,
	resource client.Object, // The controller resource to block.
	violation ValidationResult, // Details of the policy violation.
	logger logr.Logger, // Logger for structured logging.
) error {
	// Convert the `client.Object` to `*unstructured.Unstructured`.
	// This is necessary to manipulate generic fields like `spec.replicas` directly.
	unstructuredObj, ok := resource.(*unstructured.Unstructured)
	if !ok {
		// If it's not already unstructured, attempt conversion.
		converted, err := runtime.DefaultUnstructuredConverter.ToUnstructured(resource)
		if err != nil {
			logger.Error(err, "Failed to convert resource to unstructured for blocking",
				"resource", resource.GetName(), "kind", resource.GetObjectKind().GroupVersionKind().Kind)
			return fmt.Errorf("failed to convert resource to unstructured: %w", err)
		}
		unstructuredObj = &unstructured.Unstructured{Object: converted}
		// Ensure the GVK is explicitly set on the new Unstructured object.
		unstructuredObj.SetGroupVersionKind(resource.GetObjectKind().GroupVersionKind())
	}

	// Get the current number of replicas from the resource's spec.
	var currentReplicas int32
	// Use `unstructured.NestedInt64` for safe access to nested fields.
	if replicas, found, err := unstructured.NestedInt64(unstructuredObj.Object, "spec", "replicas"); err == nil && found {
		currentReplicas = int32(replicas)
	} else {
		// If replicas field is not found or cannot be read, assume 1 replica.
		// This prevents unintended behavior if the field is missing or malformed.
		currentReplicas = 1
		logger.V(1).Info("Could not determine current replicas, assuming 1 for blocking",
			"kind", unstructuredObj.GetKind(), "resource", resource.GetName(), "error", err)
	}

	if currentReplicas == 0 {
		// If the resource is already scaled to 0, just add the blocking annotations.
		logger.Info("Resource is already scaled to 0; applying policy-blocked annotations",
			"kind", unstructuredObj.GetKind(),
			"resource", resource.GetName(),
			"namespace", resource.GetNamespace())
	} else {
		// Scale the resource down to 0 replicas.
		if err := unstructured.SetNestedField(unstructuredObj.Object, int64(0), "spec", "replicas"); err != nil {
			logger.Error(err, "Failed to set replicas to 0 for controller",
				"kind", unstructuredObj.GetKind(),
				"resource", resource.GetName(),
				"namespace", resource.GetNamespace())
			errorTotal.WithLabelValues("failed_set_replicas_to_zero", unstructuredObj.GetKind()).Inc()
			return err
		}
		logger.Info("Scaling resource to 0 due to policy violation",
			"kind", unstructuredObj.GetKind(),
			"resource", resource.GetName(),
			"namespace", resource.GetNamespace(),
			"originalReplicas", currentReplicas,
			"violation", violation.ErrorMessage)
	}

	// Add or update specific annotations on the resource to mark it as blocked
	// and store its original replica count for potential future unblocking.
	annotations := resource.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[PolicyBlockedAnnotation] = "true"
	annotations[OriginalReplicasAnnotation] = fmt.Sprintf("%d", currentReplicas)
	annotations[BlockedReasonAnnotation] = violation.ErrorMessage // Provide the reason for blocking.
	resource.SetAnnotations(annotations)

	// Update the resource in Kubernetes API.
	if err := r.Update(ctx, unstructuredObj); err != nil {
		logger.Error(err, "Failed to update resource (scale down and annotate)",
			"kind", unstructuredObj.GetKind(),
			"resource", resource.GetName(),
			"namespace", resource.GetNamespace())
		errorTotal.WithLabelValues("failed_scale_down_and_annotate", unstructuredObj.GetKind()).Inc()
		return err
	}

	// Record a Kubernetes event to signal the resource has been scaled down due to policy violation.
	r.EventRecorder.Eventf(resource, corev1.EventTypeWarning, "PolicyViolation",
		"Resource %s scaled to 0 due to policy violation: %s", resource.GetName(), violation.ErrorMessage)

	return nil // Successfully scaled down and annotated.
}

// handleGenericResourceBlocking handles blocking for resources that are not Pods or common controllers.
// The default blocking action for such resources is direct deletion.
func (r *ClusterPolicyValidatorReconciler) handleGenericResourceBlocking(
	ctx context.Context,
	resource client.Object, // The generic Kubernetes resource to delete.
	violation ValidationResult, // Details of the policy violation.
	logger logr.Logger, // Logger for structured logging.
) error {
	logger.Info("Deleting generic resource due to policy violation",
		"kind", resource.GetObjectKind().GroupVersionKind().Kind,
		"resource", resource.GetName(),
		"namespace", resource.GetNamespace(),
		"violation", violation.ErrorMessage)

	// Attempt to delete the resource. `client.IgnoreNotFound` prevents an error
	// if the resource was already deleted.
	if err := r.Delete(ctx, resource); client.IgnoreNotFound(err) != nil {
		logger.Error(err, "Failed to delete generic resource",
			"kind", resource.GetObjectKind().GroupVersionKind().Kind,
			"resource", resource.GetName(),
			"namespace", resource.GetNamespace())
		errorTotal.WithLabelValues("failed_to_delete_resource", resource.GetObjectKind().GroupVersionKind().Kind).Inc()
		return err
	}

	// Record a Kubernetes event to signal the resource's deletion.
	r.EventRecorder.Eventf(resource, corev1.EventTypeWarning, "PolicyViolation",
		"Resource %s deleted due to policy violation: %s", resource.GetName(), violation.ErrorMessage)

	return nil // Resource successfully deleted or already gone.
}

// handleWarnAction processes a "warn" action for a policy violation.
// For a "warn" action, no modification is made to the resource.
// Instead, a Kubernetes event of type `Warning` is emitted on the resource,
// providing visibility about the detected violation.
func (r *ClusterPolicyValidatorReconciler) handleWarnAction(
	ctx context.Context,
	resource client.Object, // The resource for which the warning is issued.
	violation ValidationResult, // Details of the warning violation.
	logger logr.Logger, // Logger for structured logging.
) error {
	logger.Info("Policy warning detected for resource",
		"resource", resource.GetName(),
		"kind", resource.GetObjectKind().GroupVersionKind().Kind,
		"policy", violation.PolicyName,
		"rule", violation.RuleName,
		"severity", violation.Severity,
		"message", violation.ErrorMessage)

	// Emit a Kubernetes event of type "Warning" on the resource.
	r.EventRecorder.Eventf(resource, corev1.EventTypeWarning, "PolicyViolation",
		"Policy violation detected for resource %s: %s (Policy: %s, Rule: %s, Severity: %s)",
		resource.GetName(), violation.ErrorMessage, violation.PolicyName, violation.RuleName, violation.Severity)
	return nil
}

// handleAuditAction processes an "audit" action for a policy violation.
// Similar to "warn", no modification is made to the resource.
// A Kubernetes event of type `Normal` (or informational) is emitted,
// indicating that the resource was flagged for auditing purposes.
func (r *ClusterPolicyValidatorReconciler) handleAuditAction(
	ctx context.Context,
	resource client.Object, // The resource for which the audit event is generated.
	violation ValidationResult, // Details of the audit violation.
	logger logr.Logger, // Logger for structured logging.
) error {
	logger.Info("Policy audit detected for resource",
		"resource", resource.GetName(),
		"kind", resource.GetObjectKind().GroupVersionKind().Kind,
		"policy", violation.PolicyName,
		"rule", violation.RuleName,
		"severity", violation.Severity,
		"message", violation.ErrorMessage)

	// Emit a Kubernetes event of type "Normal" (informational) on the resource.
	r.EventRecorder.Eventf(resource, corev1.EventTypeNormal, "PolicyAudit",
		"Policy audit: Resource %s flagged by policy %s (Rule: %s, Severity: %s)",
		resource.GetName(), violation.PolicyName, violation.RuleName, violation.Severity)
	return nil
}

// handleDeploymentViolation is a helper function specifically for handling violations
// that originate from Pods managed by a ReplicaSet, which in turn is managed by a Deployment.
// Its purpose is to find the parent Deployment and apply the blocking action to it,
// ensuring that the controller managing the Pod is scaled down.
func (r *ClusterPolicyValidatorReconciler) handleDeploymentViolation(
	ctx context.Context,
	namespace, replicaSetName string, // Namespace and name of the ReplicaSet owner.
	violation ValidationResult, // Details of the violation to apply to the Deployment.
	logger logr.Logger, // Logger for structured logging.
) error {
	// Step 1: Get the ReplicaSet that owns the violating Pod.
	replicaSet := &appsv1.ReplicaSet{}
	namespacedName := types.NamespacedName{Namespace: namespace, Name: replicaSetName}
	if err := r.Get(ctx, namespacedName, replicaSet); err != nil {
		logger.Error(err, "Failed to get ReplicaSet to find parent Deployment", "replicaSet", namespacedName)
		return fmt.Errorf("failed to get ReplicaSet %s: %w", replicaSetName, err)
	}

	// Step 2: Find the parent Deployment from the ReplicaSet's owner references.
	for _, ownerRef := range replicaSet.GetOwnerReferences() {
		if ownerRef.Kind == "Deployment" {
			deploymentName := ownerRef.Name
			logger.Info("Found parent Deployment for ReplicaSet",
				"replicaSet", replicaSetName,
				"deployment", deploymentName,
				"namespace", namespace)

			// Step 3: Get the parent Deployment object.
			deployment := &appsv1.Deployment{}
			deploymentNamespacedName := types.NamespacedName{Namespace: namespace, Name: deploymentName}
			if err := r.Get(ctx, deploymentNamespacedName, deployment); err != nil {
				logger.Error(err, "Failed to get parent Deployment", "deployment", deploymentNamespacedName)
				return fmt.Errorf("failed to get Deployment %s: %w", deploymentName, err)
			}

			// Step 4: Check if the Deployment is already blocked by a policy.
			// This prevents redundant blocking actions and potential infinite loops.
			if deployment.GetAnnotations() != nil {
				if blocked, exists := deployment.GetAnnotations()[PolicyBlockedAnnotation]; exists && blocked == "true" {
					logger.Info("Parent Deployment is already marked as blocked; skipping further blocking action",
						"deployment", deploymentName, "namespace", namespace)
					return nil // Already blocked, no further action needed.
				}
			}

			// Step 5: If the Deployment is not already blocked, apply the blocking action to it.
			// This will scale down the Deployment to zero and add the necessary annotations.
			return r.handleControllerBlocking(ctx, deployment, violation, logger)
		}
	}

	// If no parent Deployment is found for the ReplicaSet, return an error.
	logger.Error(nil, "No parent Deployment found for ReplicaSet", "replicaSet", replicaSetName, "namespace", namespace)
	return fmt.Errorf("no parent Deployment found for ReplicaSet %s in namespace %s", replicaSetName, namespace)
}
