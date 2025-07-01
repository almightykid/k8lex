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
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"strings"

	clusterpolicynotifierv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicynotifier/v1alpha1"
	clusterpolicyupdaterv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyupdater/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ClusterPolicyUpdaterReconciler reconciles a ClusterPolicyUpdater object
type ClusterPolicyUpdaterReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Log    logr.Logger
}

// +kubebuilder:rbac:groups=clusterpolicyupdater.k8lex.io,resources=clusterpolicyupdaters,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=clusterpolicyupdater.k8lex.io,resources=clusterpolicyupdaters/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=clusterpolicyupdater.k8lex.io,resources=clusterpolicyupdaters/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=deployments;statefulsets;replicasets;daemonsets,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;update;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.20.4/pkg/reconcile
func (r *ClusterPolicyUpdaterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues(
		"controller", "clusterpolicyupdater",
		"namespace", req.Namespace,
		"name", req.Name,
	)
	log.Info("[DEBUG] Reconcile called", "request", fmt.Sprintf("%+v", req))

	// Get updater name from CRD in the same namespace (assumes 1 per ns, or adapt if multiple)
	updaters := &clusterpolicyupdaterv1alpha1.ClusterPolicyUpdaterList{}
	if err := r.List(ctx, updaters, client.InNamespace(req.Namespace)); err != nil {
		log.Error(err, "Failed to list ClusterPolicyUpdaters")
		return ctrl.Result{}, err
	}
	var currentUpdaterName string
	if len(updaters.Items) > 0 {
		currentUpdaterName = updaters.Items[0].Name
	} else {
		log.Info("[DEBUG] No ClusterPolicyUpdater found in namespace", "namespace", req.Namespace)
		return ctrl.Result{}, nil
	}

	// Obtener el recurso target (Deployment, StatefulSet, DaemonSet)
	kinds := []schema.GroupVersionKind{
		{Group: "apps", Version: "v1", Kind: "Deployment"},
		{Group: "apps", Version: "v1", Kind: "StatefulSet"},
		{Group: "apps", Version: "v1", Kind: "DaemonSet"},
	}
	var item *unstructured.Unstructured
	for _, gvk := range kinds {
		tmp := &unstructured.Unstructured{}
		tmp.SetGroupVersionKind(gvk)
		if err := r.Get(ctx, req.NamespacedName, tmp); err == nil {
			item = tmp
			break
		}
	}
	if item == nil {
		log.Info("[DEBUG] Resource not found for this reconcile", "req.NamespacedName", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	annotations := item.GetAnnotations()
	if annotations == nil {
		log.Info("[DEBUG] Resource has no annotations, skipping", "resource", item.GetName(), "namespace", item.GetNamespace())
		return ctrl.Result{}, nil
	}

	if annotations["k8lex.io/clusterpolicyupdater"] != currentUpdaterName {
		log.Info("[DEBUG] Resource not for this updater, skipping", "resource", item.GetName(), "namespace", item.GetNamespace(), "expected", currentUpdaterName, "found", annotations["k8lex.io/clusterpolicyupdater"])
		return ctrl.Result{}, nil
	}

	log.Info("[DEBUG] Resource has updater annotation, attempting update", "resource", item.GetName(), "namespace", item.GetNamespace(), "updater", currentUpdaterName)
	var originalReplicas *int64
	if replicas, found, _ := unstructured.NestedInt64(item.Object, "spec", "replicas"); found {
		originalReplicas = &replicas
	}
	updated := false
	for _, updater := range updaters.Items {
		for _, rule := range updater.Spec.UpdaterRules {
			for _, update := range rule.Update {
				if strings.Contains(update.Key, "[*]") {
					keyParts := parseWildcardPath(update.Key)
					log.Info("Attempting wildcard update", "key", update.Key, "parsed", keyParts, "resource", item.GetName())
					upd, err := updateFieldWithWildcard(item.Object, keyParts, update.Value, log, item.GetName())
					if err != nil {
						log.Error(err, "Wildcard update failed", "key", update.Key, "resource", item.GetName())
					}
					updated = updated || upd
					continue
				}
				keyPath := strings.Split(update.Key, ".")
				log.Info("Attempting direct field update", "key", update.Key, "resource", item.GetName())
				current, found, _ := unstructured.NestedFieldNoCopy(item.Object, keyPath...)
				if !found {
					log.Info("Field to update not found, skipping", "key", update.Key, "resource", item.GetName())
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
		log.Info("Resource was updated, applying changes", "resource", item.GetName(), "namespace", item.GetNamespace())
		if originalReplicas != nil {
			_ = unstructured.SetNestedField(item.Object, *originalReplicas, "spec", "replicas")
		}
		if err := r.Update(ctx, item); err != nil {
			log.Error(err, "Failed to update resource", "name", item.GetName(), "kind", item.GetKind())
		} else {
			log.Info("Resource updated by ClusterPolicyUpdater", "name", item.GetName(), "kind", item.GetKind())
		}
		// Clean updater annotation after update
		maxRetries := 5
		for i := 0; i < maxRetries; i++ {
			annotations := item.GetAnnotations()
			delete(annotations, "k8lex.io/clusterpolicyupdater")
			item.SetAnnotations(annotations)
			if err := r.Update(ctx, item); err != nil {
				if apierrors.IsConflict(err) {
					log.Info("[DEBUG] Conflict cleaning updater annotation, retrying", "attempt", i+1, "resource", item.GetName())
					// Refresh resource before retrying
					errGet := r.Get(ctx, client.ObjectKey{Namespace: item.GetNamespace(), Name: item.GetName()}, item)
					if errGet != nil {
						log.Error(errGet, "[DEBUG] Failed to refresh resource after conflict", "resource", item.GetName())
						break
					}
					continue
				}
				log.Error(err, "Failed to clear updater annotation after update", "resource", item.GetName())
			} else {
				log.Info("Updater annotation cleared after update", "resource", item.GetName())
				// Send Slack message if configured
				for _, updater := range updaters.Items {
					for _, rule := range updater.Spec.UpdaterRules {
						if rule.Notification.Enabled && rule.Notification.NotifierRef.Name != "" {
							notifier := &clusterpolicynotifierv1alpha1.ClusterPolicyNotifier{}
							err := r.Get(ctx, client.ObjectKey{Name: rule.Notification.NotifierRef.Name, Namespace: rule.Notification.NotifierRef.Namespace}, notifier)
							if err == nil && notifier.Spec.SlackWebhookUrl != "" {
								for _, update := range rule.Update {
									msg := fmt.Sprintf("Resource %s updated by updater %s\n\nSetting %s to %s\n\nDescription: %s", item.GetName(), updater.Name, update.Key, update.Value, rule.Notification.Message)
									_ = sendSlackMessage(notifier.Spec.SlackWebhookUrl, msg, log)
								}
							}
						}
					}
				}
				break
			}
		}
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ClusterPolicyUpdaterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Log = mgr.GetLogger().WithName("updater-controller")
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&clusterpolicyupdaterv1alpha1.ClusterPolicyUpdater{})

	resourceTypes := []client.Object{
		&appsv1.Deployment{},
		&appsv1.StatefulSet{},
		&appsv1.DaemonSet{},
	}
	annotationPredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldAnn := e.ObjectOld.GetAnnotations()
			newAnn := e.ObjectNew.GetAnnotations()
			return oldAnn["k8lex.io/clusterpolicyupdater"] != newAnn["k8lex.io/clusterpolicyupdater"]
		},
		CreateFunc: func(e event.CreateEvent) bool {
			ann := e.Object.GetAnnotations()
			return ann["k8lex.io/clusterpolicyupdater"] != ""
		},
		DeleteFunc:  func(e event.DeleteEvent) bool { return false },
		GenericFunc: func(e event.GenericEvent) bool { return false },
	}
	for _, obj := range resourceTypes {
		builder = builder.Watches(
			obj,
			&handler.EnqueueRequestForObject{},
		).WithEventFilter(annotationPredicate)
	}

	return builder.Complete(r)
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

// updateFieldWithWildcard actualiza todos los elementos de un array en una ruta con [*]
func updateFieldWithWildcard(obj map[string]interface{}, path []string, value interface{}, log logr.Logger, resourceName string) (bool, error) {
	// Buscar el índice del [*]
	wildcardIdx := -1
	for i, p := range path {
		if p == "[*]" {
			wildcardIdx = i
			break
		}
	}
	if wildcardIdx == -1 || wildcardIdx == 0 || wildcardIdx == len(path)-1 {
		return false, fmt.Errorf("invalid wildcard path: %v", path)
	}
	// Obtener el array
	arrayPath := path[:wildcardIdx]
	array, found, err := unstructured.NestedSlice(obj, arrayPath...)
	if err != nil || !found {
		log.V(1).Info("Array not found for wildcard update", "path", arrayPath, "resource", resourceName)
		return false, nil
	}
	updated := false
	for i, elem := range array {
		if elemMap, ok := elem.(map[string]interface{}); ok {
			finalKey := path[wildcardIdx+1:]
			current, found, _ := unstructured.NestedFieldNoCopy(elemMap, finalKey...)
			if found && current == value {
				log.Info("Field already has desired value, skipping", "container", i, "key", finalKey, "resource", resourceName)
				continue
			}
			if err := unstructured.SetNestedField(elemMap, value, finalKey...); err != nil {
				log.Error(err, "Failed to set field in array element", "container", i, "key", finalKey, "resource", resourceName)
				continue
			}
			array[i] = elemMap
			updated = true
			log.Info("Field updated in array element", "container", i, "key", finalKey, "new_value", value, "resource", resourceName)
		}
	}
	if updated {
		if err := unstructured.SetNestedSlice(obj, array, arrayPath...); err != nil {
			log.Error(err, "Failed to update array after wildcard update", "path", arrayPath, "resource", resourceName)
			return false, err
		}
	}
	return updated, nil
}

// sendSlackMessage envía un mensaje a un webhook de Slack
func sendSlackMessage(webhookURL, message string, log logr.Logger) error {
	payload := map[string]interface{}{"text": message}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Error(err, "Failed to marshal Slack message")
		return err
	}
	resp, err := http.Post(webhookURL, "application/json", strings.NewReader(string(jsonData)))
	if err != nil {
		log.Error(err, "Failed to send Slack message")
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("Slack webhook returned status: %d", resp.StatusCode)
		log.Error(err, "Slack webhook error")
		return err
	}
	return nil
}

// Reemplazo el split del path para soportar '[*]' correctamente
func parseWildcardPath(key string) []string {
	parts := strings.Split(key, ".")
	var result []string
	for _, part := range parts {
		if strings.Contains(part, "[*]") {
			result = append(result, strings.Replace(part, "[*]", "", 1))
			result = append(result, "[*]")
		} else {
			result = append(result, part)
		}
	}
	return result
}
