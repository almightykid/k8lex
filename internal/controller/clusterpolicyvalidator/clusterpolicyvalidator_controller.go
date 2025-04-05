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
	"strings"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/go-logr/logr"
	"github.com/itchyny/gojq"

	clusterpolicyvalidatorv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyvalidator/v1alpha1"
)

var allowedKinds = map[string]bool{
	"Pod":                     true,
	"Deployment":              true,
	"StatefulSet":             true,
	"ReplicaSet":              true,
	"ConfigMap":               true,
	"PersistentVolume":        true,
	"PersistentVolumeClaim":   true,
	"Service":                 true,
	"Ingress":                 true,
	"Namespace":               true,
	"HorizontalPodAutoscaler": true,
	"CronJob":                 true,
	"PodDisruptionBudget":     true,
	"NetworkPolicy":           true,
	"Secret":                  true,
}

var kindToGVK = map[string]schema.GroupVersionKind{
	"Pod":                     {Group: "", Version: "v1", Kind: "Pod"},
	"Deployment":              {Group: "apps", Version: "v1", Kind: "Deployment"},
	"StatefulSet":             {Group: "apps", Version: "v1", Kind: "StatefulSet"},
	"ReplicaSet":              {Group: "apps", Version: "v1", Kind: "ReplicaSet"},
	"ConfigMap":               {Group: "", Version: "v1", Kind: "ConfigMap"},
	"PersistentVolume":        {Group: "", Version: "v1", Kind: "PersistentVolume"},
	"PersistentVolumeClaim":   {Group: "", Version: "v1", Kind: "PersistentVolumeClaim"},
	"Service":                 {Group: "", Version: "v1", Kind: "Service"},
	"Ingress":                 {Group: "networking.k8s.io", Version: "v1", Kind: "Ingress"},
	"Namespace":               {Group: "", Version: "v1", Kind: "Namespace"},
	"HorizontalPodAutoscaler": {Group: "autoscaling", Version: "v2", Kind: "HorizontalPodAutoscaler"},
	"CronJob":                 {Group: "batch", Version: "v1", Kind: "CronJob"},
	"PodDisruptionBudget":     {Group: "policy", Version: "v1", Kind: "PodDisruptionBudget"},
	"NetworkPolicy":           {Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"},
	"Secret":                  {Group: "", Version: "v1", Kind: "Secret"},
}

// ClusterPolicyValidatorReconciler reconciles a ClusterPolicyValidator object
type ClusterPolicyValidatorReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=clusterpolicyvalidator.k8lex.io,resources=clusterpolicyvalidators,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=clusterpolicyvalidator.k8lex.io,resources=clusterpolicyvalidators/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=clusterpolicyvalidator.k8lex.io,resources=clusterpolicyvalidators/finalizers,verbs=update

// fieldExists checks if a given key exists within a Kubernetes resource
func fieldExists(resource *unstructured.Unstructured, fieldPath string) bool {
	values, err := extractValues(resource, fieldPath)
	return err == nil && len(values) > 0
}

// validateKey checks if a given key exists within a Kubernetes resource
func validateKey(ctx context.Context, c client.Client, gvk schema.GroupVersionKind, namespace, name, key string) (bool, error) {
	resource := &unstructured.Unstructured{}
	resource.SetGroupVersionKind(gvk)

	if err := c.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, resource); err != nil {
		return false, err
	}

	return fieldExists(resource, key), nil
}

// extractValues retrieves values for a given field path from the resource, handling array wildcards (*).
func extractValues(resource *unstructured.Unstructured, keyPath string) ([]interface{}, error) {
	// Transformar "spec.containers[*].image" a jq-compatible: ".spec.containers[].image"
	jqExpr := "." + strings.ReplaceAll(keyPath, "[*]", "[]")
	return evaluateJQ(resource, jqExpr)
}

// evaluateJQ runs a jq expression on a Kubernetes resource and returns the results
func evaluateJQ(resource *unstructured.Unstructured, query string) ([]interface{}, error) {
	input := resource.Object

	// Parsear la expresión jq
	q, err := gojq.Parse(query)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jq query: %w", err)
	}

	// Compilar la query
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

// Reconcile handles the reconciliation logic for ClusterPolicyValidator
// func (r *ClusterPolicyValidatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
// 	logger := log.FromContext(ctx)

// 	// Fetch the ClusterPolicyValidator instance
// 	instance := &clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{}
// 	if err := r.Get(ctx, req.NamespacedName, instance); err != nil {
// 		logger.Error(err, "unable to fetch ClusterPolicyValidator")
// 		return ctrl.Result{}, client.IgnoreNotFound(err)
// 	}

// 	if err := validateConditions(ctx, r.Client, instance); err != nil {
// 		logger.Error(err, "Validation failed")
// 		return ctrl.Result{}, nil
// 	}

// 	return ctrl.Result{}, nil
// }

func (r *ClusterPolicyValidatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Listar todos los ClusterPolicyValidator definidos
	var policies clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorList
	if err := r.List(ctx, &policies); err != nil {
		logger.Error(err, "Failed to list ClusterPolicyValidator")
		return ctrl.Result{}, err
	}

	// Obtener el recurso modificado (Pod, Deployment, etc.)
	resource := &unstructured.Unstructured{}
	resource.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "", // pod va vacio
		Version: "v1",
		Kind:    "Pod",
	})
	if err := r.Get(ctx, req.NamespacedName, resource); err != nil {
		logger.Error(err, "Failed to fetch resource")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Evaluar el recurso contra las políticas
	for _, policy := range policies.Items {
		logger.Info("Validando recurso ClusterPolicyValidator", "policy", policy.Name)

		for _, rule := range policy.Spec.ValidationRules {
			for _, condition := range rule.Conditions {
				if condition.Key == "" {
					logger.Error(nil, "Key is empty in condition")
					continue
				}

				values, err := extractValues(resource, condition.Key)
				if err != nil {
					logger.Error(err, "Failed to extract values from resource", "key", condition.Key)
					continue
				}

				if !handleConditionValidation(condition.Operator, condition.Values, values, logger) {
					logger.Error(nil, "Condition validation failed", "condition", condition)
				}
			}
		}
	}

	return ctrl.Result{}, nil
}
func handlePodAction(podName, namespace string, action string, clientset *kubernetes.Clientset, logger logr.Logger) {
	switch action {
	case "Block":
		// Eliminar o marcar el pod como fallido
		err := clientset.CoreV1().Pods(namespace).Delete(context.Background(), podName, metav1.DeleteOptions{})
		if err != nil {
			logger.Error(err, "Failed to delete pod", "pod", podName)
		} else {
			logger.Info("Pod deleted due to policy violation", "pod", podName)
		}
	case "warn":
		logger.Info("Warning: Pod uses 'latest' image, which is not allowed", "pod", podName)
	case "continue":
		logger.Info("Pod allowed to continue despite policy violation", "pod", podName)
	}
}

func handleConditionValidation(operator string, conditionValues interface{}, resourceValues []interface{}, logger logr.Logger) bool {
	switch operator {
	case "NotIn":
		var foundMatch []string

		// Verificar el tipo de conditionValues y convertirlo si es necesario
		var conditionValueList []interface{}
		switch v := conditionValues.(type) {
		case []string:
			// Convertir []string a []interface{}
			for _, item := range v {
				conditionValueList = append(conditionValueList, item)
			}
		case []interface{}:
			conditionValueList = v
		default:
			logger.Error(nil, "Unsupported type for conditionValues", "type", fmt.Sprintf("%T", conditionValues))
			return false
		}

		// Ahora conditionValueList es de tipo []interface{}
		for _, resourceValue := range resourceValues {
			// Asegurarse de que resourceValue y conditionValue son cadenas
			resourceStr := fmt.Sprintf("%v", resourceValue)
			for _, conditionValue := range conditionValueList {
				conditionStr := fmt.Sprintf("%v", conditionValue)

				// Verificar si resourceValue contiene conditionValue
				if strings.Contains(resourceStr, conditionStr) {
					foundMatch = append(foundMatch, resourceStr)
				}
			}
		}

		if len(foundMatch) > 0 {
			logger.Error(nil, "Condition violated. Values found in the list", "values", foundMatch)
			return false
		}
		return true

	case "In":
		// Implementar lógica para "In" si es necesario
		return false

	default:
		logger.Error(nil, "Unsupported operator", "operator", operator)
		return false
	}
}

func getGVKFromKind(kind string) (schema.GroupVersionKind, bool) {
	gvk, ok := kindToGVK[kind]
	return gvk, ok
}

func validateConditions(ctx context.Context, c client.Client, cpv *clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator) error {
	logger := log.FromContext(ctx)

	for _, rule := range cpv.Spec.ValidationRules {
		logger.Info("Processing rule", "name", rule.Name)

		for _, kind := range rule.MatchResources.Kinds {
			if !allowedKinds[kind] {
				logger.Info("Skipping resource, not in allowed kinds", "kind", kind)
				continue
			}

			gvk, ok := getGVKFromKind(kind)
			if !ok {
				logger.Error(nil, "Could not determine GVK for kind", "kind", kind)
				continue
			}

			// List all matching resources (simplified, assumes Namespaced scope)
			resourceList := &unstructured.UnstructuredList{}
			resourceList.SetGroupVersionKind(schema.GroupVersionKind{
				Group:   gvk.Group,
				Version: gvk.Version,
				Kind:    gvk.Kind + "List",
			})
			if err := c.List(ctx, resourceList); err != nil {
				logger.Error(err, "Failed to list resources", "gvk", gvk)
				continue
			}

			for _, resource := range resourceList.Items {
				for _, condition := range rule.Conditions {
					if condition.Key == "" {
						logger.Error(nil, "Key cannot be empty")
						continue
					}

					values, err := extractValues(&resource, condition.Key)
					if err != nil {
						logger.Error(err, "Failed to extract values", "key", condition.Key)
						continue
					}

					for _, expected := range condition.Values {
						if handleConditionValidation(condition.Operator, expected, values, logger) {
							logger.Info("Condition validated", "key", condition.Key, "expected", expected)
						} else {
							logger.Error(nil, "Condition failed", "key", condition.Key, "expected", expected)
						}
					}
				}
			}
		}
	}
	return nil
}

func (r *ClusterPolicyValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Pod{}).
		Watches(&v1.Pod{}, &handler.EnqueueRequestForObject{}).
		Complete(r)
}
