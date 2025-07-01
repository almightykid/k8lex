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

package clusterpolicyupdater

import (
	"context"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"strings"

	clusterpolicynotifierv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicynotifier/v1alpha1"
	clusterpolicyupdaterv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyupdater/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ClusterPolicyUpdaterReconciler reconciles a ClusterPolicyUpdater object
type ClusterPolicyUpdaterReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=clusterpolicyupdater.k8lex.io,resources=clusterpolicyupdaters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=clusterpolicyupdater.k8lex.io,resources=clusterpolicyupdaters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=clusterpolicyupdater.k8lex.io,resources=clusterpolicyupdaters/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;replicasets;daemonsets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the ClusterPolicyUpdater object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.4/pkg/reconcile
func (r *ClusterPolicyUpdaterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	updater := &clusterpolicyupdaterv1alpha1.ClusterPolicyUpdater{}
	err := r.Get(ctx, req.NamespacedName, updater)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Usar el nombre del recurso ClusterPolicyUpdater como identificador
	myUpdaterName := updater.Name

	log.Info("ClusterPolicyUpdater reconciliation started",
		"updater", myUpdaterName,
		"namespace", req.Namespace,
		"rules_count", len(updater.Spec.UpdaterRules))

	scalableGVKs := []schema.GroupVersionKind{
		{Group: "apps", Version: "v1", Kind: "Deployment"},
		{Group: "apps", Version: "v1", Kind: "StatefulSet"},
		{Group: "apps", Version: "v1", Kind: "DaemonSet"},
		// Note: We exclude ReplicaSet because they inherit from their parent controllers
		// and should not be updated directly
	}

	for _, gvk := range scalableGVKs {
		list := &unstructured.UnstructuredList{}
		list.SetGroupVersionKind(gvk)

		// Try to list from all namespaces first
		if err := r.List(ctx, list); err != nil {
			log.Error(err, "Failed to list resources from all namespaces", "gvk", gvk)
			continue
		}

		// If we don't find resources in k8lex namespace, try listing specifically from k8lex
		foundInK8lex := false
		for _, item := range list.Items {
			if item.GetNamespace() == "k8lex" {
				foundInK8lex = true
				break
			}
		}

		if !foundInK8lex {
			log.Info("No resources found in k8lex namespace, trying specific namespace listing", "gvk", gvk)
			// Try listing specifically from k8lex namespace
			k8lexList := &unstructured.UnstructuredList{}
			k8lexList.SetGroupVersionKind(gvk)
			if err := r.List(ctx, k8lexList, client.InNamespace("k8lex")); err != nil {
				log.Error(err, "Failed to list resources from k8lex namespace", "gvk", gvk)
			} else {
				log.Info("Found resources in k8lex namespace", "gvk", gvk, "count", len(k8lexList.Items))
				// Merge the lists
				list.Items = append(list.Items, k8lexList.Items...)
			}
		}

		log.Info("Found resources to check", "gvk", gvk, "count", len(list.Items), "updater", myUpdaterName)

		// Debug: List all namespaces found
		namespaces := make(map[string]int)
		for _, item := range list.Items {
			ns := item.GetNamespace()
			namespaces[ns]++
		}
		log.Info("Resources by namespace", "namespaces", namespaces, "gvk", gvk)
		for _, item := range list.Items {
			log.Info("Checking resource", "name", item.GetName(), "namespace", item.GetNamespace(), "kind", item.GetKind())
			annotations := item.GetAnnotations()
			if annotations == nil {
				continue
			}

			// Log all resources with k8lex annotations for debugging
			if val, ok := annotations["k8lex.io/clusterpolicyupdater"]; ok {
				log.Info("Found resource with updater annotation",
					"resource", item.GetName(),
					"namespace", item.GetNamespace(),
					"annotation_value", val,
					"expected", myUpdaterName)
			}

			if val, ok := annotations["k8lex.io/clusterpolicyupdater"]; !ok || val != myUpdaterName {
				log.V(1).Info("Resource not for this updater, skipping", "resource", item.GetName(), "expected", myUpdaterName, "found", val)
				continue
			}

			var originalReplicas *int64
			if replicas, found, _ := unstructured.NestedInt64(item.Object, "spec", "replicas"); found {
				originalReplicas = &replicas
			}

			updated := false
			for _, rule := range updater.Spec.UpdaterRules {
				for _, update := range rule.Update {
					// Handle special case for container images
					if update.Key == "spec.template.spec.containers[*].image" {
						containers, found, _ := unstructured.NestedSlice(item.Object, "spec", "template", "spec", "containers")
						if !found {
							log.V(1).Info("Containers not found", "resource", item.GetName())
							continue
						}

						// Update all container images
						for i, container := range containers {
							if containerMap, ok := container.(map[string]interface{}); ok {
								if currentImage, exists := containerMap["image"]; exists {
									if currentImage == update.Value {
										log.Info("Container image already has desired value, skipping", "container", i, "image", currentImage, "resource", item.GetName())
										continue
									}
									containerMap["image"] = update.Value
									containers[i] = containerMap
									updated = true
									log.Info("Container image updated", "container", i, "old_image", currentImage, "new_image", update.Value, "resource", item.GetName())
								}
							}
						}

						if updated {
							if err := unstructured.SetNestedSlice(item.Object, containers, "spec", "template", "spec", "containers"); err != nil {
								log.Error(err, "Failed to update containers", "resource", item.GetName())
								updated = false
							}
						}
					} else {
						// Handle other fields normally
						keyPath := strings.Split(update.Key, ".")
						current, found, _ := unstructured.NestedFieldNoCopy(item.Object, keyPath...)
						if !found {
							log.V(1).Info("Field to update not found", "key", update.Key, "resource", item.GetName())
							continue
						}
						if current == update.Value {
							log.Info("Field already has desired value, skipping update", "key", update.Key, "resource", item.GetName())
							continue
						}
						if err := unstructured.SetNestedField(item.Object, update.Value, keyPath...); err != nil {
							log.Error(err, "Failed to set field", "key", update.Key, "value", update.Value)
							continue
						}
						updated = true
						log.Info("Field updated", "key", update.Key, "value", update.Value, "resource", item.GetName())
					}
				}
			}

			if updated {
				if originalReplicas != nil {
					_ = unstructured.SetNestedField(item.Object, *originalReplicas, "spec", "replicas")
				}
				if err := r.Update(ctx, &item); err != nil {
					log.Error(err, "Failed to update resource", "name", item.GetName(), "kind", item.GetKind())
					continue
				}
				log.Info("Resource updated by ClusterPolicyUpdater", "name", item.GetName(), "kind", item.GetKind())
				// Limpieza de anotación tras update
				annotations["k8lex.io/clusterpolicyupdater"] = ""
				item.SetAnnotations(annotations)
				_ = r.Update(ctx, &item)
				// Send notification if enabled and Notifier exists
				for _, rule := range updater.Spec.UpdaterRules {
					if rule.Notification.Enabled && isNotifierEnabledAndExists(ctx, r.Client, rule.Notification.NotifierRef, log) {
						msg := rule.Notification.Message
						if msg == "" {
							msg = "Resource updated by ClusterPolicyUpdater."
						}
						log.Info("Sending update notification", "message", msg)
						// Here you would call your notification sending logic, e.g. SendCustomNotification(ctx, notifierRef, msg)
					} else {
						log.Info("Update notification not sent: not enabled or notifier does not exist", "resource", item.GetName(), "rule", rule.Name)
					}
				}
			}
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterPolicyUpdaterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&clusterpolicyupdaterv1alpha1.ClusterPolicyUpdater{}).
		Named("clusterpolicyupdater").
		Complete(r)
}

// Helper to check if Notifier is enabled and exists (phase == Ready)
func isNotifierEnabledAndExists(ctx context.Context, c client.Client, notifierRef clusterpolicyupdaterv1alpha1.Ref, logger logr.Logger) bool {
	if notifierRef.Name == "" {
		logger.Info("NotifierRef.Name is empty, skipping notification")
		return false
	}
	notifier := &clusterpolicynotifierv1alpha1.ClusterPolicyNotifier{}
	err := c.Get(ctx, client.ObjectKey{Name: notifierRef.Name, Namespace: notifierRef.Namespace}, notifier)
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
