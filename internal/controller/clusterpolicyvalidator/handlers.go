package clusterpolicyvalidator

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	clusterpolicynotifierv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicynotifier/v1alpha1"
	clusterpolicyvalidatorv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyvalidator/v1alpha1"
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
	policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator, // Lista de policies for searching for custom message.
	logger logr.Logger, // Logger for structured logging.
) (ctrl.Result, error) {
	// Iterate over each detected violation.
	for _, violation := range violations {
		// Execute the action defined by the policy (e.g., "block", "warn", "audit").
		if err := r.handleResourceAction(ctx, foundResource, resourceGVK.Kind, violation, policies, logger); err != nil {
			// If an error occurs during action handling, check if it's a retryable error
			logger.Error(err, "Failed to handle resource action for violation",
				"resource", foundResource.GetName(),
				"policy", violation.PolicyName,
				"action", violation.Action)

			// For conflict errors, let controller-runtime handle the retry automatically
			if apierrors.IsConflict(err) {
				return ctrl.Result{}, err
			}

			// For other errors, requeue after a delay
			return ctrl.Result{RequeueAfter: DefaultRequeueDelay}, nil
		}

		// If the action taken was "block", stop processing further violations for this resource.
		// A blocking action is decisive, and subsequent actions are irrelevant as the resource is being prevented.
		if strings.ToLower(violation.Action) == "block" {
			logger.Info("Resource blocked due to policy violation; stopping further violation processing",
				"policy", violation.PolicyName,
				"rule", violation.RuleName,
				"resource", foundResource.GetName(),
				"kind", resourceGVK.Kind)

			logger.Info("Blocking action taken, no further violations processed for this resource")
			return ctrl.Result{}, nil // Return an empty result, indicating no requeue is immediately needed.
		}
	}
	// After handling all (non-blocking) violations, update the resource's annotations
	// to reflect the presence and details of any violations. This provides visibility
	// into the resource's policy compliance state.
	return ctrl.Result{}, r.updateViolationAnnotations(ctx, resource, violations, logger)
}

// handleResourceAction dispatches the appropriate handler function based on the
// `Action` defined in the `ValidationResult`. This function now implements advanced logic according to the action and updater.
func (r *ClusterPolicyValidatorReconciler) handleResourceAction(
	ctx context.Context,
	resource client.Object, // The Kubernetes resource (e.g., Pod, Deployment) that violated the policy.
	kind string, // The Kind of the resource (e.g., "Pod", "Deployment").
	violation ValidationResult, // The details of the policy violation, including the action to take.
	policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator, // List of policies to look for the updater.
	logger logr.Logger, // Logger for structured logging.
) error {
	// Find notification and updater configuration
	var notificationEnabled bool
	var notifierRef clusterpolicyvalidatorv1alpha1.Ref
	var customMessage string = violation.ErrorMessage
	for _, policy := range policies {
		if policy.Name == violation.PolicyName {
			for _, rule := range policy.Spec.ValidationRules {
				if rule.Name == violation.RuleName {
					if rule.Notification.Message != "" {
						customMessage = rule.Notification.Message
					}
					notificationEnabled = rule.Notification.Enabled
					notifierRef = rule.Notification.NotifierRef
					break
				}
			}
			break
		}
	}

	action := strings.ToLower(violation.Action)

	switch action {
	case "continue":
		logger.Info("Action is 'continue': no updater, no notification")
		return nil
	case "warn":
		logger.Info("Action is 'warn': no updater, send notification if enabled")
		if notificationEnabled && isNotifierEnabledAndExists(ctx, r.Client, notifierRef, logger) {
			if err := r.SendPolicyViolationNotification(ctx, resource.GetName(), violation.RuleName, customMessage, "warn"); err != nil {
				logger.Error(err, "Failed to send policy violation notification (warn)", "resource", resource.GetName(), "policy", violation.PolicyName, "rule", violation.RuleName)
			} else {
				logger.Info("Policy violation notification sent successfully (warn)", "resource", resource.GetName(), "policy", violation.PolicyName)
			}
		} else {
			logger.Info("Notification not sent: not enabled or notifier does not exist (warn)", "resource", resource.GetName(), "policy", violation.PolicyName, "rule", violation.RuleName)
		}
		return nil
	case "block":
		updaterName, updaterKey := getUpdaterNameAndKey(policies, violation.PolicyName, violation.RuleName)
		validatorKey := normalizeKey(violation.ResourcePath)
		if updaterName != "" && normalizeKey(updaterKey) == validatorKey {
			// Hay updater y las rutas coinciden: solo anotar para updater, nunca escalar a 0
			maxRetries := 5
			for i := 0; i < maxRetries; i++ {
				annotations := resource.GetAnnotations()
				if annotations == nil {
					annotations = map[string]string{}
				}
				annotations["k8lex.io/clusterpolicyupdater"] = updaterName
				resource.SetAnnotations(annotations)
				err := r.Update(ctx, resource)
				if err == nil {
					logger.Info("Resource annotated for updater (paths match)", "resource", resource.GetName(), "key", validatorKey)
					break
				}
				if apierrors.IsConflict(err) {
					logger.Info("Conflict annotating for updater, retrying", "attempt", i+1, "resource", resource.GetName())
					_ = r.Get(ctx, client.ObjectKey{Namespace: resource.GetNamespace(), Name: resource.GetName()}, resource)
					continue
				}
				logger.Error(err, "Failed to annotate for updater", "resource", resource.GetName())
			}
			return nil
		}
		if updaterName != "" && normalizeKey(updaterKey) != validatorKey {
			logger.Error(nil, "Updater key does not match validator key, not annotating for updater", "validatorKey", validatorKey, "updaterKey", normalizeKey(updaterKey), "resource", resource.GetName())
			return nil
		}
		// No hay updater: escalar a 0 directamente
		logger.Info("No updater configured, scaling resource to 0", "resource", resource.GetName())
		if err := r.handleControllerBlocking(ctx, resource, violation, policies, logger); err != nil {
			logger.Error(err, "Failed to block resource (no updater)", "resource", resource.GetName())
		}
		return nil
	default:
		logger.Info("Unknown action, skipping", "action", action)
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
	policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator, // Lista de policies for searching for the updater.
	logger logr.Logger, // Logger for structured logging.
) error {
	// Dispatch to specialized blocking functions based on resource Kind.
	switch kind {
	case "Pod":
		// Pods might need special handling if they are managed by a controller (e.g., Deployment).
		return r.handlePodBlocking(ctx, resource, violation, policies, logger)
	case "Deployment", "ReplicaSet", "DaemonSet", "StatefulSet":
		// Controller resources are typically scaled down to zero to prevent them from running.
		return r.handleControllerBlocking(ctx, resource, violation, policies, logger)
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
	policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator, // Lista de policies for searching for the updater.
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
				return r.handleDeploymentViolation(ctx, resource.GetNamespace(), ownerRef.Name, violation, policies, logger)
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
	policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator, // Lista de policies for searching for the updater.
	logger logr.Logger, // Logger for structured logging.
) error {
	// Validate input parameters
	if resource == nil {
		return fmt.Errorf("resource cannot be nil")
	}
	if r.EventRecorder == nil {
		return fmt.Errorf("event recorder is not initialized")
	}
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
	annotations := unstructuredObj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	// Evitar doble acción: si ya está bloqueado y tiene anotación de updater, no hacer nada
	if annotations[PolicyBlockedAnnotation] == "true" && annotations["k8lex.io/clusterpolicyupdater"] != "" {
		logger.Info("Resource already blocked and annotated for updater; skipping duplicate action",
			"resource", resource.GetName(), "namespace", resource.GetNamespace())
		return nil
	}
	// Obtener el nombre del updater de la regla
	updaterName, _ := getUpdaterNameAndKey(policies, violation.PolicyName, violation.RuleName)
	if updaterName == "" {
		logger.V(1).Info("No updater name specified in rule; skipping updater annotation (warn)",
			"resource", resource.GetName(), "policy", violation.PolicyName, "rule", violation.RuleName)
	} else {
		annotations["k8lex.io/clusterpolicyupdater"] = updaterName
	}
	annotations[PolicyBlockedAnnotation] = "true"
	annotations[OriginalReplicasAnnotation] = fmt.Sprintf("%d", currentReplicas)
	annotations[BlockedReasonAnnotation] = violation.ErrorMessage // Provide the reason for blocking.
	unstructuredObj.SetAnnotations(annotations)

	// Update the resource in Kubernetes API.
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		if err := r.Update(ctx, unstructuredObj); err != nil {
			if apierrors.IsConflict(err) {
				logger.Info("Resource update conflict, retrying", "attempt", i+1, "kind", unstructuredObj.GetKind(), "resource", unstructuredObj.GetName(), "namespace", unstructuredObj.GetNamespace())
				_ = r.Get(ctx, client.ObjectKey{Namespace: unstructuredObj.GetNamespace(), Name: unstructuredObj.GetName()}, unstructuredObj)
				continue
			}
			logger.Error(err, "Failed to update resource (non-conflict error)", "kind", unstructuredObj.GetKind(), "resource", unstructuredObj.GetName(), "namespace", unstructuredObj.GetNamespace())
			return err
		}
		break
	}

	// Record a Kubernetes event to signal the resource has been scaled down due to policy violation.
	eventMessage := fmt.Sprintf("Resource %s scaled to 0 due to policy violation (Policy: %s, Rule: %s): %s",
		unstructuredObj.GetName(), violation.PolicyName, violation.RuleName, violation.ErrorMessage)
	r.EventRecorder.Eventf(unstructuredObj, corev1.EventTypeWarning, "PolicyViolation", eventMessage)

	// Send notification to Slack if enabled and resource was actually scaled down (not already blocked)
	wasAlreadyBlocked := annotations[PolicyBlockedAnnotation] == "true" && annotations["k8lex.io/clusterpolicyupdater"] != ""
	if !wasAlreadyBlocked {
		var notificationEnabled bool
		var notifierRef clusterpolicyvalidatorv1alpha1.Ref
		var customMessage string = violation.ErrorMessage

		// Find notification configuration from policies
		for _, policy := range policies {
			if policy.Name == violation.PolicyName {
				for _, rule := range policy.Spec.ValidationRules {
					if rule.Name == violation.RuleName {
						if rule.Notification.Message != "" {
							customMessage = rule.Notification.Message
						}
						notificationEnabled = rule.Notification.Enabled
						notifierRef = rule.Notification.NotifierRef
						break
					}
				}
				break
			}
		}

		// Send notification if enabled and notifier exists
		if notificationEnabled && isNotifierEnabledAndExists(ctx, r.Client, notifierRef, logger) {
			if err := r.SendPolicyViolationNotification(ctx, unstructuredObj.GetName(), violation.RuleName, customMessage, "block"); err != nil {
				logger.Error(err, "Failed to send policy violation notification",
					"resource", unstructuredObj.GetName(),
					"policy", violation.PolicyName,
					"rule", violation.RuleName)
			} else {
				logger.Info("Policy violation notification sent successfully",
					"resource", unstructuredObj.GetName(),
					"policy", violation.PolicyName)
			}
		} else {
			logger.Info("Notification not sent: not enabled or notifier does not exist",
				"resource", unstructuredObj.GetName(),
				"policy", violation.PolicyName,
				"rule", violation.RuleName)
		}
	} else {
		logger.Info("Notification skipped: resource was already blocked",
			"resource", unstructuredObj.GetName(),
			"policy", violation.PolicyName)
	}

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
		"message", violation.ErrorMessage)

	// Emit a Kubernetes event of type "Warning" on the resource.
	r.EventRecorder.Eventf(resource, corev1.EventTypeWarning, "PolicyViolation",
		"Policy violation detected for resource %s: %s (Policy: %s, Rule: %s)",
		resource.GetName(), violation.ErrorMessage, violation.PolicyName, violation.RuleName)
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
		"message", violation.ErrorMessage)

	// Emit a Kubernetes event of type "Normal" (informational) on the resource.
	r.EventRecorder.Eventf(resource, corev1.EventTypeNormal, "PolicyAudit",
		"Policy audit: Resource %s flagged by policy %s (Rule: %s)",
		resource.GetName(), violation.PolicyName, violation.RuleName)
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
	policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator, // List of policies to look for the updater.
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
			return r.handleControllerBlocking(ctx, deployment, violation, policies, logger)
		}
	}

	// If no parent Deployment is found for the ReplicaSet, return an error.
	logger.Error(nil, "No parent Deployment found for ReplicaSet", "replicaSet", replicaSetName, "namespace", namespace)
	return fmt.Errorf("no parent Deployment found for ReplicaSet %s in namespace %s", replicaSetName, namespace)
}

// Helper to get the updater name and key for a given policy and rule
func getUpdaterNameAndKey(policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator, policyName, ruleName string) (string, string) {
	for _, policy := range policies {
		if policy.Name == policyName {
			for _, rule := range policy.Spec.ValidationRules {
				if strings.ToLower(rule.Action) == "block" && rule.Name == ruleName && rule.Update.UpdaterRef.Name != "" {
					if len(rule.Conditions) > 0 {
						return rule.Update.UpdaterRef.Name, rule.Conditions[0].Key
					}
					return rule.Update.UpdaterRef.Name, ""
				}
			}
		}
	}
	return "", ""
}

// Helper to normalize keys by ignoring case and whitespace
func normalizeKey(key string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, " ", ""), "\t", ""))
}

// Helper to check if the Notifier is enabled and exists
func isNotifierEnabledAndExists(ctx context.Context, c client.Client, notifierRef clusterpolicyvalidatorv1alpha1.Ref, logger logr.Logger) bool {
	if notifierRef.Name == "" {
		logger.Info("NotifierRef.Name is empty, skipping notification")
		return false
	}
	notifier := &clusterpolicynotifierv1alpha1.ClusterPolicyNotifier{}
	err := c.Get(ctx, types.NamespacedName{Name: notifierRef.Name, Namespace: notifierRef.Namespace}, notifier)
	if err != nil {
		logger.Info("Notifier resource not found, skipping notification", "name", notifierRef.Name, "namespace", notifierRef.Namespace)
		return false
	}
	if notifier.Status.Phase != clusterpolicynotifierv1alpha1.NotifierPhaseReady {
		logger.Info("Notifier resource exists but is not Ready, skipping notification", "name", notifierRef.Name, "namespace", notifierRef.Namespace, "phase", notifier.Status.Phase)
		return false
	}
	return true
}
