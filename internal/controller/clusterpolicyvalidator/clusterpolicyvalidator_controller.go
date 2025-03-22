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

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	clusterpolicyvalidatorv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyvalidator/v1alpha1"
	"github.com/go-logr/logr"
)

// ClusterPolicyValidatorReconciler reconciles a ClusterPolicyValidator object
type ClusterPolicyValidatorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=clusterpolicyvalidator.k8lex.io,resources=clusterpolicyvalidators,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=clusterpolicyvalidator.k8lex.io,resources=clusterpolicyvalidators/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=clusterpolicyvalidator.k8lex.io,resources=clusterpolicyvalidators/finalizers,verbs=update

// isValidKey checks if the provided key follows a valid format
func isValidKey(key string) bool {
	var keyRegex = regexp.MustCompile(`^[a-zA-Z0-9._/-]+$`)
	return keyRegex.MatchString(key)
}

// fieldExists checks if a given key exists within a Kubernetes resource
func fieldExists(resource *unstructured.Unstructured, fieldPath string) bool {
	// Convert the key into a slice (e.g., "spec.containers[*].image" → ["spec", "containers[*]", "image"])
	pathParts := strings.Split(fieldPath, ".")

	// If the path includes a list like `containers[*]`
	for i, part := range pathParts {
		if strings.Contains(part, "[*]") {
			key := strings.TrimSuffix(part, "[*]")

			// Get the list (e.g., containers)
			containerList, found, _ := unstructured.NestedSlice(resource.Object, pathParts[:i]...)
			if !found {
				return false
			}

			// Iterate through each item in the list and check for the `image` field
			for _, item := range containerList {
				if containerMap, ok := item.(map[string]interface{}); ok {
					if _, exists := containerMap[key]; exists {
						// Check for the next part (e.g., image)
						if len(pathParts) > i+1 {
							if _, exists := containerMap[pathParts[i+1]]; exists {
								return true
							}
						}
					}
				}
			}
			return false
		}
	}

	// If no `[*]`, use the normal logic for direct field lookup
	value, found, _ := unstructured.NestedFieldCopy(resource.Object, pathParts...)
	return found && value != nil
}

// validateKey checks if a given key exists within a Kubernetes resource
func validateKey(ctx context.Context, c client.Client, gvk schema.GroupVersionKind, namespace, name, key string) (bool, error) {
	// Create an unstructured object to dynamically retrieve any resource
	resource := &unstructured.Unstructured{}
	resource.SetGroupVersionKind(gvk)

	// Fetch the Kubernetes resource
	err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, resource)
	if err != nil {
		return false, err
	}

	// Check if the key exists anywhere in the resource
	return fieldExists(resource, key), nil
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ClusterPolicyValidatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	clusterPolicyValidator := &clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{}

	if err := r.Get(ctx, req.NamespacedName, clusterPolicyValidator); err != nil {
		logger.Error(err, "unable to fetch ClusterPolicyValidator")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if len(clusterPolicyValidator.Spec.ValidationRules) > 0 {
		for _, rule := range clusterPolicyValidator.Spec.ValidationRules {
			logger.Info("Processing rule", "name", rule.Name)

			for _, kind := range rule.MatchResources.Kinds {
				logger.Info("Processing resource kind", "kind", kind)

				for _, condition := range rule.Conditions {

					if condition.Key == "" {
						logger.Error(nil, "Key cannot be empty")
						return ctrl.Result{}, nil
					}

					if !isValidKey(condition.Key) {
						logger.Error(nil, "Invalid key format", "key", condition.Key)
						return ctrl.Result{}, nil
					}

					logger.Info("Processing condition", "key", condition.Key, "operator", condition.Operator)

					gvk, err := getGVKFromKind(kind)
					if err != nil {
						logger.Error(err, "Could not determine GVK for kind", "kind", kind)
						continue
					}

					logger.Info("Validating resource", "GVK", gvk, "Namespace", req.Namespace, "Name", req.Name)

					exists, err := validateKey(ctx, r.Client, gvk, req.Namespace, req.Name, condition.Key)
					if err != nil {
						logger.Error(err, "Error fetching resource to validate key", "key", condition.Key, "kind", kind)
						continue
					}
					if !exists {
						logger.Error(nil, "Key does not exist in resource", "key", condition.Key, "kind", kind)
						continue
					}

					logger.Info("Key exists in resource", "key", condition.Key, "kind", kind)

					// Now validate the condition using the extracted function
					for _, values := range condition.Values {
						valid := handleConditionValidation(condition.Operator, values, condition.Values, logger)
						if !valid {
							continue
						}
					}
				}
			}
		}
	}

	return ctrl.Result{}, nil
}

// handleConditionValidation handles the validation logic for different operators.
func handleConditionValidation(operator string, values interface{}, conditionValue interface{}, logger logr.Logger) bool {
	switch operator {
	case "In":
		logger.Info("Checking if value is in list", "value", values)
		// Check if the value is in the list
		if !contains(values, conditionValue) {
			logger.Error(nil, "Value is not in list", "value", values)
			return false
		}
		logger.Info("Value is in list", "value", values)

	case "NotIn":
		logger.Info("Checking if value is not in list", "value", values)
		// Check if the value is not in the list
		if contains(values, conditionValue) {
			logger.Error(nil, "Value is in list", "value", values)
			return false
		}
		logger.Info("Value is not in list", "value", values)

	case "Exists":
		logger.Info("Checking if key exists in resource", "key", conditionValue)
		// Check if the key exists in the resource
		if !valuesExists(values) {
			logger.Error(nil, "Key does not exist in resource", "key", conditionValue)
			return false
		}
		logger.Info("Key exists in resource", "key", conditionValue)

	case "DoesNotExist":
		logger.Info("Checking if key does not exist in resource", "key", conditionValue)
		// Check if the key does not exist in the resource
		if valuesExists(values) {
			logger.Error(nil, "Key exists in resource", "key", conditionValue)
			return false
		}
		logger.Info("Key does not exist in resource", "key", conditionValue)

	case "GreaterThan":
		logger.Info("Checking if value is greater than", "value", values)
		// Check if the value is greater than
		if !greaterThan(values, conditionValue) {
			logger.Error(nil, "Value is not greater than", "value", values)
			return false
		}
		logger.Info("Value is greater than", "value", values)

	case "LessThan":
		logger.Info("Checking if value is less than", "value", values)
		// Check if the value is less than
		if !lessThan(values, conditionValue) {
			logger.Error(nil, "Value is not less than", "value", values)
			return false
		}
		logger.Info("Value is less than", "value", values)

	case "Equal":
		logger.Info("Checking if value is equal to", "value", values)
		// Check if the value is equal to
		if !equal(values, conditionValue) {
			logger.Error(nil, "Value is not equal to", "value", values)
			return false
		}
		logger.Info("Value is equal to", "value", values)

	case "NotEqual":
		logger.Info("Checking if value is not equal to", "value", values)
		// Check if the value is not equal to
		if equal(values, conditionValue) {
			logger.Error(nil, "Value is equal to", "value", values)
			return false
		}
		logger.Info("Value is not equal to", "value", values)

	case "GreaterThanOrEqual":
		logger.Info("Checking if value is greater than or equal to", "value", values)
		// Check if the value is greater than or equal to
		if !greaterThanOrEqual(values, conditionValue) {
			logger.Error(nil, "Value is not greater than or equal to", "value", values)
			return false
		}
		logger.Info("Value is greater than or equal to", "value", values)

	case "LessThanOrEqual":
		logger.Info("Checking if value is less than or equal to", "value", values)
		// Check if the value is less than or equal to
		if !lessThanOrEqual(values, conditionValue) {
			logger.Error(nil, "Value is not less than or equal to", "value", values)
			return false
		}
		logger.Info("Value is less than or equal to", "value", values)

	case "DoesNotMatch":
		logger.Info("Checking if value does not match", "value", values)
		// Check if the value does not match
		if !doesNotMatch(values, conditionValue) {
			logger.Error(nil, "Value does match", "value", values)
			return false
		}
		logger.Info("Value does not match", "value", values)

	case "Matches":
		logger.Info("Checking if value matches", "value", values)
		// Check if the value matches
		if !matches(values, conditionValue) {
			logger.Error(nil, "Value does not match", "value", values)
			return false
		}
		logger.Info("Value matches", "value", values)

	default:
		logger.Error(nil, "Unsupported operator", "operator", operator)
		return false
	}
	return true
}

// matches verifica si un valor de tipo cadena coincide con un patrón de expresión regular.
func matches(value string, pattern string) bool {
	matched, err := regexp.MatchString(pattern, value)
	return err == nil && matched
}

// doesNotMatch verifica si un valor de tipo cadena **no** coincide con un patrón de expresión regular.
func doesNotMatch(value string, pattern string) bool {
	matched, err := regexp.MatchString(pattern, value)
	return err == nil && !matched
}

// lessThanOrEqual verifica si el valor de `value` es menor o igual que `comparisonValue`.
// Asume que ambos son números.
func lessThanOrEqual(value string, comparisonValue string) bool {
	val, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false
	}

	compVal, err := strconv.ParseFloat(comparisonValue, 64)
	if err != nil {
		return false
	}

	return val <= compVal
}

// greaterThanOrEqual verifica si el valor de `value` es mayor o igual que `comparisonValue`.
// Asume que ambos son números.
func greaterThanOrEqual(value string, comparisonValue string) bool {
	val, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false
	}

	compVal, err := strconv.ParseFloat(comparisonValue, 64)
	if err != nil {
		return false
	}

	return val >= compVal
}

// contains verifica si un valor está en una lista de valores
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// equal verifica si dos valores son iguales
func equal(value1 string, value2 string) bool {
	return value1 == value2
}

// greaterThan verifica si value1 es mayor que value2
func greaterThan(value1 string, value2 string) bool {
	val1, err := strconv.ParseFloat(value1, 64)
	if err != nil {
		return false
	}

	val2, err := strconv.ParseFloat(value2, 64)
	if err != nil {
		return false
	}

	return val1 > val2
}

// lessThan verifica si value1 es menor que value2
func lessThan(value1 string, value2 string) bool {
	val1, err := strconv.ParseFloat(value1, 64)
	if err != nil {
		return false
	}

	val2, err := strconv.ParseFloat(value2, 64)
	if err != nil {
		return false
	}

	return val1 < val2
}

// getGVKFromKind maps resource kinds to their respective GroupVersionKind
func getGVKFromKind(kind string) (schema.GroupVersionKind, error) {
	switch kind {
	case "Pod":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}, nil
	case "Deployment":
		return schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}, nil
	case "StatefulSet":
		return schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "StatefulSet"}, nil
	case "ReplicaSet":
		return schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "ReplicaSet"}, nil
	case "ConfigMap":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"}, nil
	case "Volume", "PersistentVolume":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "PersistentVolume"}, nil
	case "PersistentVolumeClaim":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "PersistentVolumeClaim"}, nil
	case "Service":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Service"}, nil
	case "Ingress":
		return schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "Ingress"}, nil
	case "Namespace":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}, nil
	case "HorizontalPodAutoscaler":
		return schema.GroupVersionKind{Group: "autoscaling", Version: "v2", Kind: "HorizontalPodAutoscaler"}, nil
	case "CronJob":
		return schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "CronJob"}, nil
	case "PodDisruptionBudget":
		return schema.GroupVersionKind{Group: "policy", Version: "v1", Kind: "PodDisruptionBudget"}, nil
	case "NetworkPolicy":
		return schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"}, nil
	case "Secret":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}, nil
	default:
		return schema.GroupVersionKind{}, fmt.Errorf("unsupported kind: %s", kind)
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterPolicyValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{}).
		Complete(r)
}
