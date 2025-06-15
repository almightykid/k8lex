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
	"net/http"
	"os"
	"strings"
	"time"

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
	clusterpolicyvalidatorcontroller "github.com/almightykid/k8lex/internal/controller/clusterpolicyvalidator"
	"github.com/go-logr/logr"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("main")
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
	// This determines which resources the VALIDATOR needs to watch dynamically
	tmpClient, err := client.New(ctrl.GetConfigOrDie(), client.Options{Scheme: scheme})
	if err != nil {
		setupLog.Error(err, "unable to create temporary client for validator dynamic setup")
		os.Exit(1)
	}

	var allPolicies clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorList
	if err := tmpClient.List(context.Background(), &allPolicies); err != nil {
		setupLog.Error(err, "unable to list existing ClusterPolicyValidators for dynamic setup. Starting with minimal watches.")
	}

	// Build a map of resource types that the VALIDATOR needs to watch dynamically
	validatorDynamicGVKs := make(map[schema.GroupVersionKind]struct{})

	if len(allPolicies.Items) > 0 {
		setupLog.Info("Found existing policies, determining dynamic resource types for validator", "policy_count", len(allPolicies.Items))

		for _, policy := range allPolicies.Items {
			setupLog.Info("Processing existing policy for validator dynamic watching", "policy", policy.Name)
			for _, rule := range policy.Spec.ValidationRules {
				for _, kind := range rule.MatchResources.Kinds {
					gvk := resolveKindToGVK(kind, scheme, setupLog)
					if gvk.Kind != "" {
						validatorDynamicGVKs[gvk] = struct{}{}
						setupLog.Info("Validator will dynamically watch resource type", "kind", kind, "gvk", gvk, "policy", policy.Name)
					}
				}
			}
		}
	} else {
		setupLog.Info("No existing policies found. Validator will start with minimal dynamic watches.")
		setupLog.Info("IMPORTANT: When you create policies with new resource types, you'll need to restart the operator for validator to watch those resources.")
	}

	setupLog.Info("Validator Dynamic Resource Types",
		"count", len(validatorDynamicGVKs),
		"message", "Only validator watches these resources dynamically for performance")

	// Print warning if running in minimal mode
	if len(validatorDynamicGVKs) == 0 {
		setupLog.Info("🔥 VALIDATOR DYNAMIC MODE: Currently no dynamic resources to watch. Additional resources will be watched when policies are created (requires restart).")
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

	// Set up controllers - each handles its own resource watching independently
	setupLog.Info("Setting up controllers with clean separation...")

	// ✅ PRIMERO: Create ClusterPolicyNotifier Controller
	setupLog.Info("Setting up ClusterPolicyNotifier controller...")
	notifierController := &clusterpolicynotifiercontroller.ClusterPolicyNotifierReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		// ✅ AÑADIR HTTPClient para las requests de Slack
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	if err = notifierController.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterPolicyNotifier")
		os.Exit(1)
	}
	setupLog.Info("✅ ClusterPolicyNotifier controller registered")

	// ClusterPolicyValidator Controller (with dynamic watching for performance)
	policyController := &clusterpolicyvalidatorcontroller.ClusterPolicyValidatorReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		DynamicGVKs:        validatorDynamicGVKs, // Only pass dynamic GVKs it needs,
		NotifierController: notifierController,
	}
	policyController.FailureMode = clusterpolicyvalidatorcontroller.FailSafe
	policyController.ConflictResolution = clusterpolicyvalidatorcontroller.ConflictResolutionHighestSeverity

	if err = policyController.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterPolicyValidator")
		os.Exit(1)
	}
	setupLog.Info("✅ ClusterPolicyValidator controller registered with dynamic watching", "dynamic_resources", len(validatorDynamicGVKs))

	// ClusterPolicyNotifier Controller (standard watching - only its own CRD)
	// if err = (&clusterpolicynotifiercontroller.ClusterPolicyNotifierReconciler{
	// 	Client: mgr.GetClient(),
	// 	Scheme: mgr.GetScheme(),
	// }).SetupWithManager(mgr); err != nil {
	// 	setupLog.Error(err, "unable to create controller", "controller", "ClusterPolicyNotifier")
	// 	os.Exit(1)
	// }
	// setupLog.Info("✅ ClusterPolicyNotifier controller registered")

	// ClusterPolicyUpdater Controller (standard watching - only its own CRD)
	if err = (&clusterpolicyupdatercontroller.ClusterPolicyUpdaterReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterPolicyUpdater")
		os.Exit(1)
	}
	setupLog.Info("✅ ClusterPolicyUpdater controller registered")

	// ClusterPolicySet Controller (standard watching - only its own CRD)
	if err = (&clusterpolicysetcontroller.ClusterPolicySetReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterPolicySet")
		os.Exit(1)
	}
	setupLog.Info("✅ ClusterPolicySet controller registered")

	// Add restart detector only for validator's dynamic resources
	if err := mgr.Add(&ValidatorRestartDetector{
		Client:             mgr.GetClient(),
		Log:                setupLog.WithName("validator-restart-detector"),
		CurrentWatchedGVKs: validatorDynamicGVKs,
		CheckInterval:      30 * time.Second,
	}); err != nil {
		setupLog.Error(err, "unable to add validator restart detector")
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

	setupLog.Info("starting manager with clean controller separation")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// ValidatorRestartDetector monitors for new resource types that the VALIDATOR needs to watch
// This is specific to the validator's dynamic watching needs
type ValidatorRestartDetector struct {
	Client             client.Client
	Log                logr.Logger
	CurrentWatchedGVKs map[schema.GroupVersionKind]struct{}
	CheckInterval      time.Duration
}

func (r *ValidatorRestartDetector) Start(ctx context.Context) error {
	r.Log.Info("Starting validator restart detector", "check_interval", r.CheckInterval)

	ticker := time.NewTicker(r.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.Log.Info("Validator restart detector stopped")
			return nil
		case <-ticker.C:
			if err := r.checkForNewValidatorResourceTypes(ctx); err != nil {
				r.Log.Error(err, "Error checking for new validator resource types")
			}
		}
	}
}

func (r *ValidatorRestartDetector) checkForNewValidatorResourceTypes(ctx context.Context) error {
	var allPolicies clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorList
	if err := r.Client.List(ctx, &allPolicies); err != nil {
		return err
	}

	// Check if any policies require new resource types for the validator
	for _, policy := range allPolicies.Items {
		for _, rule := range policy.Spec.ValidationRules {
			for _, kind := range rule.MatchResources.Kinds {
				gvk := resolveKindToGVK(kind, runtime.NewScheme(), r.Log)
				if gvk.Kind != "" {
					if _, exists := r.CurrentWatchedGVKs[gvk]; !exists {
						r.Log.Info("🔄 RESTART REQUIRED: Validator needs to watch new resource type",
							"kind", kind,
							"gvk", gvk,
							"policy", policy.Name,
							"message", "Please restart the operator for validator to watch this resource type")

						// You could implement automatic restart here if desired
						// For now, just log the requirement
					}
				}
			}
		}
	}

	return nil
}

// resolveKindToGVK is a helper function to map simple Kind strings to their full GVKs.
// This function prioritizes current stable APIs over deprecated ones.
func resolveKindToGVK(kind string, scheme *runtime.Scheme, logger logr.Logger) schema.GroupVersionKind {
	// FIRST: Check manual mappings for current stable APIs to avoid deprecated versions
	switch strings.ToLower(kind) {
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
	case "secret":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}
	case "namespace":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}
	case "ingress":
		return schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "Ingress"}
	case "networkpolicy":
		return schema.GroupVersionKind{Group: "networking.k8s.io", Version: "v1", Kind: "NetworkPolicy"}
	case "job":
		return schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "Job"}
	case "cronjob":
		return schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "CronJob"}
	case "horizontalpodautoscaler", "hpa":
		return schema.GroupVersionKind{Group: "autoscaling", Version: "v2", Kind: "HorizontalPodAutoscaler"}
	case "role":
		return schema.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "Role"}
	case "clusterrole":
		return schema.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRole"}
	case "rolebinding":
		return schema.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "RoleBinding"}
	case "clusterrolebinding":
		return schema.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "ClusterRoleBinding"}
	case "serviceaccount":
		return schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ServiceAccount"}
	}

	// SECOND: Look in scheme, but prioritize stable versions
	var candidates []schema.GroupVersionKind
	for gvk := range scheme.AllKnownTypes() {
		if gvk.Kind == kind {
			candidates = append(candidates, gvk)
		}
	}

	if len(candidates) > 0 {
		// Prioritize by group and version stability
		best := prioritizeStableGVK(candidates, logger)
		if best.Kind != "" {
			return best
		}
	}

	logger.Info("Unknown or unresolvable Kind for GVK mapping, skipping", "kind", kind)
	return schema.GroupVersionKind{} // Return empty GVK for unknown kinds
}

// prioritizeStableGVK selects the most stable API version from candidates
func prioritizeStableGVK(candidates []schema.GroupVersionKind, logger logr.Logger) schema.GroupVersionKind {
	if len(candidates) == 0 {
		return schema.GroupVersionKind{}
	}

	// Priority order: prefer stable APIs over beta/alpha, and current groups over deprecated
	priorities := map[string]int{
		// Core APIs (highest priority)
		"v1": 1000,

		// Stable APIs
		"apps/v1":                      900,
		"networking.k8s.io/v1":         890,
		"batch/v1":                     880,
		"autoscaling/v2":               870,
		"rbac.authorization.k8s.io/v1": 860,
		"policy/v1":                    850,
		"storage.k8s.io/v1":            840,

		// Beta APIs (lower priority)
		"apps/v1beta1":              500,
		"apps/v1beta2":              510,
		"networking.k8s.io/v1beta1": 490,
		"batch/v1beta1":             480,
		"autoscaling/v2beta1":       470,
		"autoscaling/v2beta2":       480,

		// Alpha APIs (lowest priority)
		"apps/v1alpha1":              100,
		"networking.k8s.io/v1alpha1": 90,

		// Deprecated APIs (very low priority)
		"extensions/v1beta1": 10,
	}

	var best schema.GroupVersionKind
	bestPriority := -1

	for _, candidate := range candidates {
		apiVersion := candidate.Group
		if apiVersion == "" {
			apiVersion = candidate.Version
		} else {
			apiVersion = candidate.Group + "/" + candidate.Version
		}

		priority, exists := priorities[apiVersion]
		if !exists {
			// Unknown API version, give it medium priority
			priority = 300
		}

		if priority > bestPriority {
			bestPriority = priority
			best = candidate
		}
	}

	if best.Kind != "" {
		logger.V(2).Info("Selected best GVK from candidates",
			"selected", best,
			"priority", bestPriority,
			"total_candidates", len(candidates))
	}

	return best
}
