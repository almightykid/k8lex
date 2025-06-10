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

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"os"
	"strings"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	clusterpolicynotifierv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicynotifier/v1alpha1"
	clusterpolicysetv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyset/v1alpha1"
	clusterpolicyupdaterv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyupdater/v1alpha1"
	clusterpolicyvalidatorv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyvalidator/v1alpha1"
	clusterpolicynotifiercontroller "github.com/almightykid/k8lex/internal/controller/clusterpolicynotifier"
	clusterpolicysetcontroller "github.com/almightykid/k8lex/internal/controller/clusterpolicyset"
	clusterpolicyupdatercontroller "github.com/almightykid/k8lex/internal/controller/clusterpolicyupdater"
	"github.com/almightykid/k8lex/internal/controller/clusterpolicyvalidator"
	clusterpolicyvalidatorcontroller "github.com/almightykid/k8lex/internal/controller/clusterpolicyvalidator"
	"github.com/go-logr/logr"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(clusterpolicyvalidatorv1alpha1.AddToScheme(scheme))
	utilruntime.Must(clusterpolicyupdaterv1alpha1.AddToScheme(scheme))
	utilruntime.Must(clusterpolicysetv1alpha1.AddToScheme(scheme))
	utilruntime.Must(clusterpolicynotifierv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", false,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Create a temporary client to list existing ClusterPolicyValidators
	// to determine the initial set of watched resources.
	// This client doesn't need to be cached, just for initial setup.
	tmpClient, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		setupLog.Error(err, "unable to create temporary client for initial watcher setup")
		os.Exit(1)
	}

	var allPolicies clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorList
	if err := tmpClient.List(context.Background(), &allPolicies); err != nil {
		setupLog.Error(err, "unable to list existing ClusterPolicyValidators for initial watcher setup. Starting with no dynamic watches.")
		// We'll proceed, but the reconciler might miss events for kinds not in initially loaded policies.
		// A restart of the operator will be needed if new kinds are added.
	}

	// Build a map of unique GVKs to watch from existing policies
	watchedGVKs := make(map[schema.GroupVersionKind]struct{})
	for _, policy := range allPolicies.Items {
		for _, rule := range policy.Spec.ValidationRules {
			for _, kind := range rule.MatchResources.Kinds {
				gvk := resolveKindToGVK(kind, scheme, setupLog) // Pass scheme to resolveKindToGVK
				if gvk.Kind != "" {                             // Ensure it's a valid GVK
					watchedGVKs[gvk] = struct{}{}
				}
			}
		}
	}

	var initialWatchedResources []clusterpolicyvalidator.ResourceTypeConfig
	// Always add the ClusterPolicyValidator itself, it's implicitly watched by .For() but good to list
	// This specific GVK/Object might not be strictly needed in WatchedResources if it's the For() type
	// but it ensures it's part of the known resources if needed for other logic.
	initialWatchedResources = append(initialWatchedResources, clusterpolicyvalidator.ResourceTypeConfig{
		GVK:    clusterpolicyvalidatorv1alpha1.GroupVersion.WithKind("ClusterPolicyValidator"),
		Object: &clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{},
	})

	for gvk := range watchedGVKs {
		// Use the scheme to create an empty object for the GVK
		obj, err := scheme.New(gvk)
		if err != nil {
			setupLog.Error(err, "unable to create object for GVK for initial watcher setup", "gvk", gvk)
			continue // Skip this GVK if we can't create its object
		}
		// Ensure the object implements client.Object interface
		clientObj, ok := obj.(client.Object)
		if !ok {
			setupLog.Error(nil, "created object does not implement client.Object", "gvk", gvk)
			continue
		}
		initialWatchedResources = append(initialWatchedResources, clusterpolicyvalidator.ResourceTypeConfig{
			GVK:    gvk,
			Object: clientObj,
		})
	}

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts: tlsOpts,
	})

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		// TODO(user): TLSOpts is used to allow configuring the TLS config used for the server. If certificates are
		// not provided, self-signed certificates will be generated by default. This option is not recommended for
		// production environments as self-signed certificates do not offer the same level of trust and security
		// as certificates issued by a trusted Certificate Authority (CA). The primary risk is potentially allowing
		// unauthorized access to sensitive metrics data. Consider replacing with CertDir, CertName, and KeyName
		// to provide certificates, ensuring the server communicates using trusted and secure certificates.
		TLSOpts: tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "efa08164.k8lex.io",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}
	setupLog.Info("Initial Watched Resources collected", "resources", initialWatchedResources)
	if err = (&clusterpolicyvalidatorcontroller.ClusterPolicyValidatorReconciler{
		Client:           mgr.GetClient(),
		Scheme:           mgr.GetScheme(),
		WatchedResources: initialWatchedResources,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterPolicyValidator")
		os.Exit(1)
	}
	if err = (&clusterpolicyupdatercontroller.ClusterPolicyUpdaterReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterPolicyUpdater")
		os.Exit(1)
	}
	if err = (&clusterpolicysetcontroller.ClusterPolicySetReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterPolicySet")
		os.Exit(1)
	}
	if err = (&clusterpolicynotifiercontroller.ClusterPolicyNotifierReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterPolicyNotifier")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// resolveKindToGVK is a helper function to map simple Kind strings to their full GVKs.
// This function needs to be exhaustive for all types your operator might watch.
// It also needs access to the scheme to create empty objects for the GVK.
func resolveKindToGVK(kind string, scheme *runtime.Scheme, logger logr.Logger) schema.GroupVersionKind {
	// Loop through all known GVKs in the scheme to find a match
	for gvk := range scheme.AllKnownTypes() {
		if gvk.Kind == kind {
			// Prioritize official core and apps APIs, then custom ones.
			// This part might need refinement based on your specific needs
			// if multiple GVKs share the same Kind (e.g., "Deployment" in different groups).
			// For simplicity, we'll return the first match found.
			return gvk
		}
	}

	// Manual fallback/specific definitions for common types if scheme lookup isn't enough
	// or for types not yet added to the scheme via init() but might be configured in policies.
	switch strings.ToLower(kind) { // Use ToLower to handle case variations
	case "pod":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}
	case "deployment":
		return schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"}
	case "replicaset":
		return schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "ReplicaSet"}
	case "daemonset":
		return schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "DaemonSet"}
	case "statefulset":
		return schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "StatefulSet"}
	case "configmap":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"}
	case "persistentvolume":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "PersistentVolume"}
	case "persistentvolumeclaim":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "PersistentVolumeClaim"}
	case "service":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Service"}
	case "secret": // Common to add if you might validate secrets
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}
	case "namespace": // Common to add if you might validate namespaces
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}
	case "ingress": // Assuming networking.k8s.io/v1
		return schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "Ingress"}
		// Add more cases for other specific Kinds you expect to monitor that might not be in the default scheme
		// or for custom resources you want to watch.
	}

	logger.Info("Unknown or unresolvable Kind for GVK mapping, skipping", "kind", kind)
	return schema.GroupVersionKind{} // Return empty GVK for unknown kinds
}
