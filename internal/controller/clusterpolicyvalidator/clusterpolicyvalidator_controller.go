/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package clusterpolicyvalidator

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/go-logr/logr"
	"github.com/itchyny/gojq"

	clusterpolicyvalidatorv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyvalidator/v1alpha1"
)

// ResourceTypeConfig defines configuration for each resource type
type ResourceTypeConfig struct {
	GVK    schema.GroupVersionKind
	Object client.Object
}

// ClusterPolicyValidatorReconciler reconciles a ClusterPolicyValidator object
type ClusterPolicyValidatorReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	WatchedResources []ResourceTypeConfig
}

// +kubebuilder:rbac:groups=clusterpolicyvalidator.k8lex.io,resources=clusterpolicyvalidators,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=clusterpolicyvalidator.k8lex.io,resources=clusterpolicyvalidators/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=clusterpolicyvalidator.k8lex.io,resources=clusterpolicyvalidators/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",resources=persistentvolumes,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="apps",resources=deployments,verbs=get;list;watch;delete;update
// +kubebuilder:rbac:groups="apps",resources=replicasets,verbs=get;list;watch
// +kubebuilder:rbac:groups="apps",resources=daemonsets,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="apps",resources=statefulsets,verbs=get;list;watch;delete

// GetDefaultWatchedResources returns the default set of resources to watch
func GetDefaultWatchedResources() []ResourceTypeConfig {
	return []ResourceTypeConfig{
		{
			GVK:    schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			Object: &v1.Pod{},
		},
		{
			GVK:    schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
			Object: &v1.ConfigMap{},
		},
		{
			GVK:    schema.GroupVersionKind{Group: "", Version: "v1", Kind: "PersistentVolume"},
			Object: &v1.PersistentVolume{},
		},
		{
			GVK:    schema.GroupVersionKind{Group: "", Version: "v1", Kind: "PersistentVolumeClaim"},
			Object: &v1.PersistentVolumeClaim{},
		},
		{
			GVK:    schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Service"},
			Object: &v1.Service{},
		},
		{
			GVK:    schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
			Object: &appsv1.Deployment{},
		},
	}
}

// extractValues retrieves values for a given field path from the resource, handling array wildcards (*).
func extractValues(resource *unstructured.Unstructured, keyPath string) ([]interface{}, error) {
	// Transform "spec.containers[*].image" to jq-compatible: ".spec.containers[].image"
	jqExpr := "." + strings.ReplaceAll(keyPath, "[*]", "[]")

	// Add error handling for missing fields - return empty if field doesn't exist
	jqExpr = fmt.Sprintf("try (%s) catch empty", jqExpr)

	return evaluateJQ(resource, jqExpr)
}

// evaluateJQ runs a jq expression on a Kubernetes resource and returns the results
func evaluateJQ(resource *unstructured.Unstructured, query string) ([]interface{}, error) {
	input := resource.Object

	// Query parse jq
	q, err := gojq.Parse(query)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jq query: %w", err)
	}

	// Compile jq query
	code, err := gojq.Compile(q)
	if err != nil {
		return nil, fmt.Errorf("failed to compile jq query: %w", err)
	}

	iter := code.Run(input)

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

// Reconcile handles both ClusterPolicyValidator changes and resource validation
func (r *ClusterPolicyValidatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Check if this is a ClusterPolicyValidator resource
	var policy clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator
	if err := r.Get(ctx, req.NamespacedName, &policy); err == nil {
		logger.Info("ClusterPolicyValidator updated", "policy", policy.Name, "namespace", policy.Namespace)
		// Policy was updated, validation will happen when resources are created/updated
		// Don't validate the policy resource itself - just return
		return ctrl.Result{}, nil
	}

	// If not a policy, this should be a resource to validate
	logger.V(1).Info("Processing non-policy resource", "namespacedName", req.NamespacedName)
	return r.validateResource(ctx, req, logger)
}

func namespaceAllowed(resourceNamespace string, nsConfig clusterpolicyvalidatorv1alpha1.Namespace) bool {
	if len(nsConfig.Include) > 0 {
		for _, allowed := range nsConfig.Include {
			if resourceNamespace == allowed {
				return true
			}
		}
		return false
	}
	for _, excluded := range nsConfig.Exclude {
		if resourceNamespace == excluded {
			return false
		}
	}

	return true
}

// validateResource validates any Kubernetes resource against all ClusterPolicyValidator policies
func (r *ClusterPolicyValidatorReconciler) validateResource(ctx context.Context, req ctrl.Request, logger logr.Logger) (ctrl.Result, error) {
	// Try to get the resource as unstructured to handle any resource type
	resource := &unstructured.Unstructured{}

	// We need to determine the resource type from the request
	// We'll try each watched resource type until we find a match
	var foundResource client.Object
	var resourceGVK schema.GroupVersionKind

	logger.V(1).Info("Attempting to find resource type", "namespacedName", req.NamespacedName)

	for _, config := range r.WatchedResources {
		// Skip ClusterPolicyValidator resources - they should not be validated against policies
		if config.GVK.Kind == "ClusterPolicyValidator" {
			logger.V(1).Info("Skipping ClusterPolicyValidator in resource detection", "gvk", config.GVK)
			continue
		}

		logger.V(1).Info("Trying resource type", "kind", config.GVK.Kind, "namespacedName", req.NamespacedName)

		tempResource := config.Object.DeepCopyObject().(client.Object)
		if err := r.Get(ctx, req.NamespacedName, tempResource); err == nil {
			foundResource = tempResource
			resourceGVK = config.GVK
			logger.V(1).Info("Found matching resource", "kind", resourceGVK.Kind, "name", foundResource.GetName())
			break
		}
	}

	if foundResource == nil {
		logger.Info("Resource not found or not watched", "namespacedName", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	// Convert the found resource to unstructured for jq processing
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(foundResource)
	if err != nil {
		logger.Error(err, "Failed to convert resource to unstructured")
		return ctrl.Result{}, err
	}

	resource.Object = unstructuredObj
	resource.SetGroupVersionKind(resourceGVK)

	logger.Info("Validating resource", "kind", resourceGVK.Kind, "name", foundResource.GetName(), "namespace", foundResource.GetNamespace())

	// List all ClusterPolicyValidator policies
	var policies clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorList
	if err := r.List(ctx, &policies); err != nil {
		logger.Error(err, "Failed to list ClusterPolicyValidator")
		return ctrl.Result{}, err
	}

	// Evaluate conditions for each policy
	for _, policy := range policies.Items {
		// Check if this policy applies to this resource type
		if !r.policyAppliesToResource(policy, resourceGVK) {
			continue
		}

		if !namespaceAllowed(resource.GetNamespace(), policy.Spec.Namespaces) {
			logger.V(1).Info("Skipping resource due to namespace filtering",
				"namespace", resource.GetNamespace(),
				"policy", policy.Name)
			continue
		}

		logger.Info("Validating resource against ClusterPolicyValidator",
			"policy", policy.Name,
			"resource", foundResource.GetName(),
			"kind", resourceGVK.Kind)

		for _, rule := range policy.Spec.ValidationRules {
			// Check if this rule applies to this resource type
			if !r.ruleAppliesToResource(rule, resourceGVK) {
				continue
			}

			violated := false

			for _, condition := range rule.Conditions {
				if condition.Key == "" {
					logger.Error(nil, "Key is empty in condition")
					continue
				}

				values, err := extractValues(resource, condition.Key)
				if err != nil {
					logger.Error(err, "Failed to extract values from resource", "key", condition.Key, "resourceKind", resourceGVK.Kind)
					continue
				}

				if !handleConditionValidation(condition.Operator, condition.Values, values, logger) {
					logger.Info("Condition validation failed",
						"rule", rule.Name,
						"condition", condition,
						"resource", foundResource.GetName(),
						"kind", resourceGVK.Kind,
						"severity", rule.Severity)
					violated = true
				}
			}

			// If any condition was violated, take action based on the rule
			if violated {
				errorMsg := r.formatErrorMessage(rule.ErrorMessage, foundResource)
				r.handleResourceAction(ctx, foundResource, resourceGVK.Kind, rule.Action, rule.Severity, errorMsg, logger)
			}
		}
	}

	return ctrl.Result{}, nil
}

// policyAppliesToResource checks if a policy should be applied to a specific resource type
func (r *ClusterPolicyValidatorReconciler) policyAppliesToResource(policy clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator, resourceGVK schema.GroupVersionKind) bool {
	// Check each validation rule's matchResources
	for _, rule := range policy.Spec.ValidationRules {
		// If no kinds specified in matchResources, apply to all
		if len(rule.MatchResources.Kinds) == 0 {
			return true
		}

		// Check if this resource type is in the kinds list
		for _, kind := range rule.MatchResources.Kinds {
			if kind == resourceGVK.Kind {
				return true
			}
		}
	}

	return false
}

// ruleAppliesToResource checks if a specific validation rule applies to a resource type
func (r *ClusterPolicyValidatorReconciler) ruleAppliesToResource(rule clusterpolicyvalidatorv1alpha1.ValidationRule, resourceGVK schema.GroupVersionKind) bool {
	// If no kinds specified in matchResources, apply to all
	if len(rule.MatchResources.Kinds) == 0 {
		return true
	}

	// Check if this resource type is in the kinds list
	for _, kind := range rule.MatchResources.Kinds {
		if kind == resourceGVK.Kind {
			return true
		}
	}

	return false
}

// isParentDeploymentAlreadyBlocked checks if a pod's parent deployment is already blocked by policy
func (r *ClusterPolicyValidatorReconciler) isParentDeploymentAlreadyBlocked(ctx context.Context, resource client.Object, logger logr.Logger) bool {
	// Check if resource has owner references to ReplicaSet
	for _, ownerRef := range resource.GetOwnerReferences() {
		if ownerRef.Kind == "ReplicaSet" {
			// Get the ReplicaSet to find its parent Deployment
			replicaSet := &appsv1.ReplicaSet{}
			if err := r.Get(ctx, types.NamespacedName{Namespace: resource.GetNamespace(), Name: ownerRef.Name}, replicaSet); err != nil {
				logger.V(1).Info("Failed to get ReplicaSet", "replicaSet", ownerRef.Name, "error", err)
				return false
			}

			// Find the parent Deployment
			for _, rsOwnerRef := range replicaSet.GetOwnerReferences() {
				if rsOwnerRef.Kind == "Deployment" {
					deployment := &appsv1.Deployment{}
					if err := r.Get(ctx, types.NamespacedName{Namespace: resource.GetNamespace(), Name: rsOwnerRef.Name}, deployment); err != nil {
						logger.V(1).Info("Failed to get Deployment", "deployment", rsOwnerRef.Name, "error", err)
						return false
					}

					// Check if deployment is already blocked
					if deployment.Annotations != nil {
						if blocked, exists := deployment.Annotations["k8lex.io/policy-blocked"]; exists && blocked == "true" {
							logger.V(1).Info("Found parent deployment already blocked", "deployment", rsOwnerRef.Name)
							return true
						}
					}
				}
			}
		}
	}
	return false
}
func (r *ClusterPolicyValidatorReconciler) formatErrorMessage(template string, resource client.Object) string {
	if template == "" {
		return "Resource violates policy"
	}

	// Simple template replacement - you might want to use a proper template engine
	message := template
	message = strings.ReplaceAll(message, "{{ .metadata.name }}", resource.GetName())
	message = strings.ReplaceAll(message, "{{ .metadata.namespace }}", resource.GetNamespace())

	return message
}

// handleDeploymentViolation finds the parent deployment and takes action to prevent the infinite loop
func (r *ClusterPolicyValidatorReconciler) handleDeploymentViolation(ctx context.Context, namespace, replicaSetName string, logger logr.Logger) error {
	// Get the ReplicaSet to find its parent Deployment
	replicaSet := &appsv1.ReplicaSet{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: replicaSetName}, replicaSet); err != nil {
		return fmt.Errorf("failed to get ReplicaSet %s: %w", replicaSetName, err)
	}

	// Find the parent Deployment
	for _, ownerRef := range replicaSet.GetOwnerReferences() {
		if ownerRef.Kind == "Deployment" {
			deploymentName := ownerRef.Name
			logger.Info("Found parent Deployment, checking if already blocked", "deployment", deploymentName)

			// Get the deployment
			deployment := &appsv1.Deployment{}
			if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: deploymentName}, deployment); err != nil {
				return fmt.Errorf("failed to get Deployment %s: %w", deploymentName, err)
			}

			// Check if deployment is already blocked by policy
			if deployment.Annotations != nil {
				if blocked, exists := deployment.Annotations["k8lex.io/policy-blocked"]; exists && blocked == "true" {
					logger.Info("Deployment already blocked by policy, skipping", "deployment", deploymentName)
					return nil
				}
			}

			// Scale to zero (prevents infinite loop but keeps deployment)
			originalReplicas := *deployment.Spec.Replicas

			// If already scaled to 0, nothing to do but mark it as blocked
			if originalReplicas == 0 {
				logger.Info("Deployment already scaled to 0, marking as policy-blocked", "deployment", deploymentName)
				// Still add annotations to track it was blocked by policy
				if deployment.Annotations == nil {
					deployment.Annotations = make(map[string]string)
				}
				deployment.Annotations["k8lex.io/policy-blocked"] = "true"
				deployment.Annotations["k8lex.io/original-replicas"] = "0"
				deployment.Annotations["k8lex.io/blocked-reason"] = "Policy violation: contains 'latest' image tag"

				if err := r.Update(ctx, deployment); err != nil {
					logger.Error(err, "Failed to update deployment annotations", "deployment", deploymentName)
				}
				return nil
			}

			zero := int32(0)
			deployment.Spec.Replicas = &zero

			// Add annotation to track that this was blocked by policy
			if deployment.Annotations == nil {
				deployment.Annotations = make(map[string]string)
			}
			deployment.Annotations["k8lex.io/policy-blocked"] = "true"
			deployment.Annotations["k8lex.io/original-replicas"] = fmt.Sprintf("%d", originalReplicas)
			deployment.Annotations["k8lex.io/blocked-reason"] = "Policy violation: contains 'latest' image tag"

			// Update the deployment
			if err := r.Update(ctx, deployment); err != nil {
				return fmt.Errorf("failed to scale down Deployment %s: %w", deploymentName, err)
			}

			logger.Info("Deployment scaled down due to policy violation",
				"deployment", deploymentName,
				"originalReplicas", originalReplicas,
				"reason", "Policy violation: contains 'latest' image tag")

			return nil
		}
	}

	return fmt.Errorf("no parent Deployment found for ReplicaSet %s", replicaSetName)
}

// handleResourceAction takes action on a resource based on policy violation
func (r *ClusterPolicyValidatorReconciler) handleResourceAction(ctx context.Context, resource client.Object, kind, action, severity, errorMessage string, logger logr.Logger) {
	resourceName := resource.GetName()
	namespace := resource.GetNamespace()

	// Log the violation with severity and custom error message
	logger.Info("Policy violation detected",
		"resource", resourceName,
		"namespace", namespace,
		"kind", kind,
		"severity", severity,
		"action", action,
		"error", errorMessage)

	switch action {
	case "Block", "block":
		// Use the controller-runtime client for deletion instead of clientset
		switch kind {
		case "Pod":
			// For pods created by deployments, scale down the deployment instead
			if ownerRefs := resource.GetOwnerReferences(); len(ownerRefs) > 0 {
				for _, ownerRef := range ownerRefs {
					if ownerRef.Kind == "ReplicaSet" {
						// This pod is managed by a ReplicaSet, which is managed by a Deployment
						// Let's find and scale down the deployment
						logger.Info("Pod is managed by ReplicaSet, looking for parent Deployment", "replicaSet", ownerRef.Name)
						if err := r.handleDeploymentViolation(ctx, namespace, ownerRef.Name, logger); err != nil {
							logger.Error(err, "Failed to handle deployment violation")
						}
						return // Don't delete the pod directly
					}
				}
			}

			// If not managed by deployment, delete the pod directly
			pod := &v1.Pod{}
			pod.SetName(resourceName)
			pod.SetNamespace(namespace)
			err := r.Delete(ctx, pod)
			if err != nil {
				logger.Error(err, "Failed to delete Pod", "resource", resourceName, "error", errorMessage)
			} else {
				logger.Info("Pod deleted due to policy violation", "resource", resourceName, "reason", errorMessage)
			}
		case "ConfigMap":
			cm := &v1.ConfigMap{}
			cm.SetName(resourceName)
			cm.SetNamespace(namespace)
			err := r.Delete(ctx, cm)
			if err != nil {
				logger.Error(err, "Failed to delete ConfigMap", "resource", resourceName, "error", errorMessage)
			} else {
				logger.Info("ConfigMap deleted due to policy violation", "resource", resourceName, "reason", errorMessage)
			}
		case "PersistentVolumeClaim":
			pvc := &v1.PersistentVolumeClaim{}
			pvc.SetName(resourceName)
			pvc.SetNamespace(namespace)
			err := r.Delete(ctx, pvc)
			if err != nil {
				logger.Error(err, "Failed to delete PVC", "resource", resourceName, "error", errorMessage)
			} else {
				logger.Info("PVC deleted due to policy violation", "resource", resourceName, "reason", errorMessage)
			}
		case "PersistentVolume":
			pv := &v1.PersistentVolume{}
			pv.SetName(resourceName)
			err := r.Delete(ctx, pv)
			if err != nil {
				logger.Error(err, "Failed to delete PV", "resource", resourceName, "error", errorMessage)
			} else {
				logger.Info("PV deleted due to policy violation", "resource", resourceName, "reason", errorMessage)
			}
		case "Service":
			svc := &v1.Service{}
			svc.SetName(resourceName)
			svc.SetNamespace(namespace)
			err := r.Delete(ctx, svc)
			if err != nil {
				logger.Error(err, "Failed to delete Service", "resource", resourceName, "error", errorMessage)
			} else {
				logger.Info("Service deleted due to policy violation", "resource", resourceName, "reason", errorMessage)
			}
		case "Deployment":
			// For deployments, scale to zero instead of deleting
			deployment := &appsv1.Deployment{}
			deployment.SetName(resourceName)
			deployment.SetNamespace(namespace)

			// Get the current deployment
			if err := r.Get(ctx, types.NamespacedName{Name: resourceName, Namespace: namespace}, deployment); err != nil {
				logger.Error(err, "Failed to get Deployment for scaling", "resource", resourceName)
			} else {
				originalReplicas := *deployment.Spec.Replicas
				zero := int32(0)
				deployment.Spec.Replicas = &zero

				// Add annotation to track that this was blocked by policy
				if deployment.Annotations == nil {
					deployment.Annotations = make(map[string]string)
				}
				deployment.Annotations["k8lex.io/policy-blocked"] = "true"
				deployment.Annotations["k8lex.io/original-replicas"] = fmt.Sprintf("%d", originalReplicas)
				deployment.Annotations["k8lex.io/blocked-reason"] = errorMessage

				if err := r.Update(ctx, deployment); err != nil {
					logger.Error(err, "Failed to scale down Deployment", "resource", resourceName, "error", errorMessage)
				} else {
					logger.Info("Deployment scaled down due to policy violation", "resource", resourceName, "originalReplicas", originalReplicas, "reason", errorMessage)
				}
			}
		default:
			logger.Info("Unsupported resource type for deletion", "kind", kind, "resource", resourceName)
		}
	case "warn", "Warn":
		logger.Info("WARNING: Policy Violation",
			"kind", kind,
			"resource", resourceName,
			"namespace", namespace,
			"severity", severity,
			"message", errorMessage)
	case "continue", "Continue":
		logger.Info("Resource allowed to continue despite policy violation",
			"kind", kind,
			"resource", resourceName,
			"severity", severity,
			"message", errorMessage)
	default:
		logger.Info("Unknown action for policy violation",
			"action", action,
			"kind", kind,
			"resource", resourceName,
			"message", errorMessage)
	}
}

func handleConditionValidation(operator string, conditionValues interface{}, resourceValues []interface{}, logger logr.Logger) bool {
	switch operator {
	case "NotIn":
		var foundMatch []string
		conditionValueList := toInterfaceSlice(conditionValues, logger)
		if conditionValueList == nil {
			return false
		}
		for _, resourceValue := range resourceValues {
			resourceStr := fmt.Sprintf("%v", resourceValue)
			for _, conditionValue := range conditionValueList {
				conditionStr := fmt.Sprintf("%v", conditionValue)
				if strings.Contains(resourceStr, conditionStr) {
					foundMatch = append(foundMatch, resourceStr)
				}
			}
		}
		if len(foundMatch) > 0 {
			logger.Info("Condition violated. Values found in the list", "values", foundMatch)
			return false
		}
		return true

	case "In":
		conditionValueList := toInterfaceSlice(conditionValues, logger)
		if conditionValueList == nil {
			return false
		}
		for _, resourceValue := range resourceValues {
			resourceStr := fmt.Sprintf("%v", resourceValue)
			for _, conditionValue := range conditionValueList {
				conditionStr := fmt.Sprintf("%v", conditionValue)
				if strings.Contains(resourceStr, conditionStr) {
					logger.Info("Condition satisfied. Value found in allowed list", "value", resourceStr)
					return true
				}
			}
		}
		logger.Info("Condition violated. No values found in allowed list")
		return false

	case "Equals":
		expected := fmt.Sprintf("%v", conditionValues)
		for _, resourceValue := range resourceValues {
			if fmt.Sprintf("%v", resourceValue) == expected {
				return true
			}
		}
		return false

	case "NotEquals":
		expected := fmt.Sprintf("%v", conditionValues)
		for _, resourceValue := range resourceValues {
			if fmt.Sprintf("%v", resourceValue) == expected {
				return false
			}
		}
		return true

	case "Regex":
		pattern, ok := conditionValues.(string)
		if !ok {
			logger.Error(nil, "Regex pattern must be a string")
			return false
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			logger.Error(err, "Invalid regex pattern")
			return false
		}
		for _, resourceValue := range resourceValues {
			if re.MatchString(fmt.Sprintf("%v", resourceValue)) {
				return true
			}
		}
		return false

	case "GreaterThan", "LessThan", "GreaterThanOrEqual", "LessThanOrEqual":
		conditionFloat, err := toFloat64(conditionValues)
		if err != nil {
			logger.Error(err, "Condition value must be numeric")
			return false
		}
		for _, rv := range resourceValues {
			resourceFloat, err := toFloat64(rv)
			if err != nil {
				continue
			}
			switch operator {
			case "GreaterThan":
				if resourceFloat > conditionFloat {
					return true
				}
			case "LessThan":
				if resourceFloat < conditionFloat {
					return true
				}
			case "GreaterThanOrEqual":
				if resourceFloat >= conditionFloat {
					return true
				}
			case "LessThanOrEqual":
				if resourceFloat <= conditionFloat {
					return true
				}
			}
		}
		return false

	case "Exists":
		for _, rv := range resourceValues {
			if rv != nil && fmt.Sprintf("%v", rv) != "" {
				return true
			}
		}
		return false

	case "NotExists":
		for _, rv := range resourceValues {
			if rv != nil && fmt.Sprintf("%v", rv) != "" {
				return false
			}
		}
		return true

	default:
		logger.Error(nil, "Unsupported operator", "operator", operator)
		return false
	}
}

func toInterfaceSlice(val interface{}, logger logr.Logger) []interface{} {
	switch v := val.(type) {
	case []string:
		out := make([]interface{}, len(v))
		for i, s := range v {
			out[i] = s
		}
		return out
	case []interface{}:
		return v
	default:
		logger.Error(nil, "Unsupported type for conditionValues", "type", fmt.Sprintf("%T", val))
		return nil
	}
}

func toFloat64(val interface{}) (float64, error) {
	switch v := val.(type) {
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", val)
	}
}

// resourcePredicate creates a predicate for filtering resource events
func resourcePredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return true
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			// Only reconcile if the resource has meaningful changes
			return e.ObjectOld.GetGeneration() != e.ObjectNew.GetGeneration()
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return false // Don't validate deleted resources
		},
	}
}

// SetupWithManager sets up the controller with the Manager to watch multiple resource types
func (r *ClusterPolicyValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Set default watched resources if none specified
	if len(r.WatchedResources) == 0 {
		r.WatchedResources = GetDefaultWatchedResources()
	}

	// Use the builder pattern which is more compatible across versions
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 2,
		})

	// Add watches for each resource type
	for _, config := range r.WatchedResources {
		builder = builder.Watches(config.Object, &handler.EnqueueRequestForObject{})
	}

	return builder.Complete(r)
}

// SetupWithManagerAlternative provides setup with event filtering predicates (alternative approach)
func (r *ClusterPolicyValidatorReconciler) SetupWithManagerAlternative(mgr ctrl.Manager) error {
	// Set default watched resources if none specified
	if len(r.WatchedResources) == 0 {
		r.WatchedResources = GetDefaultWatchedResources()
	}

	// Simple approach - watch each resource type separately
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{})

	// Add individual watches
	for _, config := range r.WatchedResources {
		builder = builder.Watches(config.Object, &handler.EnqueueRequestForObject{})
	}

	return builder.WithOptions(controller.Options{
		MaxConcurrentReconciles: 2,
	}).Complete(r)
}

// NewClusterPolicyValidatorReconciler creates a new reconciler with custom watched resources
func NewClusterPolicyValidatorReconciler(client client.Client, scheme *runtime.Scheme, watchedResources []ResourceTypeConfig) *ClusterPolicyValidatorReconciler {
	return &ClusterPolicyValidatorReconciler{
		Client:           client,
		Scheme:           scheme,
		WatchedResources: watchedResources,
	}
}
