package clusterpolicyvalidator

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/go-logr/logr"

	clusterpolicyvalidatorv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyvalidator/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
)

// SetupWithManager configures the controller with the manager and establishes all necessary watches
// This method integrates enhanced features while maintaining compatibility with the existing main.go structure
// It sets up dynamic resource watching, optimized event filtering, and background maintenance tasks
func (r *ClusterPolicyValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Log = mgr.GetLogger().WithName("validator-controller")
	r.EventRecorder = mgr.GetEventRecorderFor("validator-controller")
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{})

	// Add watches for all scalable resource types
	// Note: We exclude ReplicaSet to avoid duplicate reconciliations when Deployment changes
	resourceTypes := []client.Object{
		&appsv1.Deployment{},
		&appsv1.StatefulSet{},
		&appsv1.DaemonSet{},
		&batchv1.CronJob{},
	}
	for _, obj := range resourceTypes {
		builder = builder.Watches(
			obj,
			&handler.EnqueueRequestForObject{},
		).WithEventFilter(r.createEventFilter())
	}

	return builder.WithOptions(controller.Options{
		MaxConcurrentReconciles: 5,
	}).Complete(r)
}

// createEventFilter creates a predicate to filter events and reduce unnecessary reconciliations
func (r *ClusterPolicyValidatorReconciler) createEventFilter() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			// Always process creation events
			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Only process updates if spec or metadata.annotations changed
			// This prevents reconciliations on status-only changes
			if e.ObjectOld == nil || e.ObjectNew == nil {
				return true
			}

			// Check if spec changed
			oldSpec := e.ObjectOld.GetAnnotations()["k8s.io/spec-hash"]
			newSpec := e.ObjectNew.GetAnnotations()["k8s.io/spec-hash"]
			if oldSpec != newSpec {
				return true
			}

			// Check if our policy annotations changed
			oldAnnotations := e.ObjectOld.GetAnnotations()
			newAnnotations := e.ObjectNew.GetAnnotations()

			policyAnnotations := []string{
				"k8lex.io/policy-blocked",
				"k8lex.io/original-replicas",
				"k8lex.io/blocked-reason",
				"k8lex.io/clusterpolicyupdater",
			}

			for _, ann := range policyAnnotations {
				if oldAnnotations[ann] != newAnnotations[ann] {
					return true
				}
			}

			return false
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			// Always process deletion events
			return true
		},
		GenericFunc: func(e event.GenericEvent) bool {
			// Process generic events
			return true
		},
	}
}

// Reconcile is the main reconciliation loop
func (r *ClusterPolicyValidatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := r.Log.WithValues(
		"request_namespace", req.Namespace,
		"request_name", req.Name)

	policy := &clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{}
	err := r.Get(ctx, req.NamespacedName, policy)
	if err == nil {
		logger.Info("Processing ClusterPolicyValidator configuration",
			"policy_name", policy.Name,
			"generation", policy.Generation)

		// --- BEGIN OVERLAP VALIDATION ---
		policyList := &clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorList{}
		errList := r.List(ctx, policyList)
		if errList != nil {
			logger.Error(errList, "Failed to list ClusterPolicyValidators for overlap validation")
			return ctrl.Result{}, errList
		}
		var overlapErrors []string
		for _, rule := range policy.Spec.ValidationRules {
			for _, cond := range rule.Conditions {
				for _, other := range policyList.Items {
					if other.Name == policy.Name {
						continue // skip self
					}
					for _, otherRule := range other.Spec.ValidationRules {
						for _, otherCond := range otherRule.Conditions {
							// Check for same Kind and Condition.Key
							for _, kind := range rule.MatchResources.Kinds {
								for _, otherKind := range otherRule.MatchResources.Kinds {
									if kind == otherKind && cond.Key == otherCond.Key {
										errMsg := "Overlap detected: Rule '" + rule.Name + "' (" + policy.Name + ") and Rule '" + otherRule.Name + "' (" + other.Name + ") both match Kind '" + kind + "' and path '" + cond.Key + "'"
										logger.Info(errMsg)
										overlapErrors = append(overlapErrors, errMsg)
									}
								}
							}
						}
					}
				}
			}
		}
		if len(overlapErrors) > 0 {
			// Update status with error
			policy.Status.ValidationStatus = "Invalid"
			policy.Status.ValidationErrors = overlapErrors
			errStatus := r.Status().Update(ctx, policy)
			if errStatus != nil {
				logger.Error(errStatus, "Failed to update status with overlap errors")
			}
			return ctrl.Result{}, nil
		} else {
			// Clear previous errors if any
			if policy.Status.ValidationStatus == "Invalid" || len(policy.Status.ValidationErrors) > 0 {
				policy.Status.ValidationStatus = "Valid"
				policy.Status.ValidationErrors = nil
				errStatus := r.Status().Update(ctx, policy)
				if errStatus != nil {
					logger.Error(errStatus, "Failed to clear previous overlap errors")
				}
			}
		}
		// --- END OVERLAP VALIDATION ---
		return ctrl.Result{}, nil
	} else if apierrors.IsNotFound(err) {
		logger.Info("Processing resource validation request",
			"action", "validating_resource_against_policies")
		return r.validateResource(ctx, req, logger)
	} else {
		logger.Error(err, "API error during reconciliation")
		return ctrl.Result{}, err
	}
}

// validateResource performs resource validation
func (r *ClusterPolicyValidatorReconciler) validateResource(ctx context.Context, req ctrl.Request, logger logr.Logger) (ctrl.Result, error) {
	foundResource, resourceGVK, err := r.findResource(ctx, req, logger)
	if err != nil {
		logger.Error(err, "Resource discovery failed")
		return ctrl.Result{}, err
	}
	if foundResource == nil {
		logger.Info("Resource not found in watched resource types - skipping validation",

			"namespacedName", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	if !r.isNamespaceAllowedByPredicate(foundResource.GetNamespace(), logger) {
		logger.Info("Skipping resource due to namespace filtering", "namespace", foundResource.GetNamespace())
		return ctrl.Result{}, nil
	}

	logger.Info("Resource discovered for validation",
		"resource_kind", resourceGVK.Kind,
		"resource_name", foundResource.GetName(),
		"resource_namespace", foundResource.GetNamespace())

	resource, err := r.convertToUnstructured(foundResource, resourceGVK)
	if err != nil {
		logger.Error(err, "Failed to convert resource to unstructured format for policy evaluation")
		return ctrl.Result{}, err
	}

	policyList := &clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorList{}
	err = r.List(ctx, policyList)
	if err != nil {
		logger.Error(err, "Failed to retrieve policies for validation")
		return ctrl.Result{}, err
	}
	policies := policyList.Items

	// Si el recurso está anotado para updater pero ya no incumple la regla, limpiar anotaciones y terminar
	annotations := resource.GetAnnotations()
	if annotations != nil && annotations["k8lex.io/clusterpolicyupdater"] != "" {
		// Revalidar el recurso
		violations := r.evaluatePolicies(ctx, resource, foundResource, resourceGVK, policies, logger)
		if len(violations) == 0 {
			logger.Info("Resource previously blocked, but now passes validation after updater. Clearing annotations.", "resource", resource.GetName())
			delete(annotations, "k8lex.io/clusterpolicyupdater")
			resource.SetAnnotations(annotations)
			maxRetries := 5
			for i := 0; i < maxRetries; i++ {
				if err := r.Update(ctx, resource); err != nil {
					if apierrors.IsConflict(err) {
						logger.Info("Conflict clearing updater annotation, retrying", "attempt", i+1, "resource", resource.GetName())
						_ = r.Get(ctx, client.ObjectKey{Namespace: resource.GetNamespace(), Name: resource.GetName()}, resource)
						continue
					}
					logger.Error(err, "Failed to clear updater annotation after successful update", "resource", resource.GetName())
					break
				}
				break
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, nil
	}

	violations := r.evaluatePolicies(ctx, resource, foundResource, resourceGVK, policies, logger)
	if len(violations) > 0 {
		logger.Info("Policy violations detected - initiating enforcement actions",
			"violation_count", len(violations),
			"resource", foundResource.GetName(),
			"kind", resourceGVK.Kind)
		result, err := r.handleViolations(ctx, foundResource, resource, resourceGVK, violations, policies, logger)
		return result, err
	}

	r.clearViolationAnnotations(ctx, resource, logger)
	logger.Info("Resource validation completed successfully - no policy violations detected",
		"resource", foundResource.GetName(),
		"kind", resourceGVK.Kind,
		"policies_evaluated", len(policies))

	return ctrl.Result{}, nil
}

func (e *NonRetryableError) Error() string {
	return e.Err.Error()
}

func (e *NonRetryableError) Unwrap() error {
	return e.Err
}
