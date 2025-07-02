package clusterpolicynotifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	policyv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicynotifier/v1alpha1"
	"github.com/go-logr/logr"
)

// ClusterPolicyNotifierReconciler reconciles a ClusterPolicyNotifier object
type ClusterPolicyNotifierReconciler struct {
	client.Client
	Scheme     *runtime.Scheme
	HTTPClient *http.Client
	Log        logr.Logger
}

// Simple Slack message payload
type SlackMessage struct {
	Text string `json:"text"`
}

//+kubebuilder:rbac:groups=policies.example.com,resources=clusterpolicynotifiers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=policies.example.com,resources=clusterpolicynotifiers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=policies.example.com,resources=clusterpolicynotifiers/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop
func (r *ClusterPolicyNotifierReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	logger.Info("Processing ClusterPolicyNotifier reconciliation")

	// Fetch the ClusterPolicyNotifier instance
	var notifier policyv1alpha1.ClusterPolicyNotifier
	if err := r.Get(ctx, req.NamespacedName, &notifier); err != nil {
		if errors.IsNotFound(err) {
			logger.Info("ClusterPolicyNotifier resource not found. Ignoring since object must have been deleted")
			return ctrl.Result{}, nil
		}
		logger.Error(err, "Failed to get ClusterPolicyNotifier")
		return ctrl.Result{}, err
	}

	logger.Info("ClusterPolicyNotifier found",
		"name", notifier.Name,
		"generation", notifier.Generation,
		"observed_generation", notifier.Status.ObservedGeneration)

	// Check if we already processed this generation
	if notifier.Status.ObservedGeneration == notifier.Generation {
		logger.V(1).Info("Generation already processed, skipping reconciliation")
		return ctrl.Result{}, nil
	}

	// Validate the notifier configuration
	if err := notifier.Validate(); err != nil {
		logger.Error(err, "ClusterPolicyNotifier validation failed")
		return r.updateStatus(ctx, &notifier, policyv1alpha1.NotifierPhaseError, err.Error())
	}

	logger.Info("ClusterPolicyNotifier validation successful")

	// Test the webhook by sending the configured message
	if err := r.sendSlackMessage(ctx, notifier.Spec.SlackWebhookUrl, notifier.Name+" successfully connected to this channel."); err != nil {
		logger.Error(err, "Failed to send test message to Slack")
		return r.updateStatus(ctx, &notifier, policyv1alpha1.NotifierPhaseError, fmt.Sprintf("Webhook test failed: %v", err))
	}

	logger.Info("Test message sent successfully to Slack")

	// Update status to Ready and increment counter
	notifier.Status.NotificationsSent++
	now := metav1.NewTime(time.Now())
	notifier.Status.LastSentNotification = &now

	return r.updateStatus(ctx, &notifier, policyv1alpha1.NotifierPhaseReady, "")
}

// SendMessage sends a custom message using the specified notifier
func (r *ClusterPolicyNotifierReconciler) SendMessage(ctx context.Context, notifierName, message string) error {
	logger := log.FromContext(ctx).WithValues("notifier", notifierName)

	// Get the notifier
	var notifier policyv1alpha1.ClusterPolicyNotifier
	if err := r.Get(ctx, types.NamespacedName{Name: notifierName, Namespace: "k8lex"}, &notifier); err != nil {
		return fmt.Errorf("failed to get notifier %s: %w", notifierName, err)
	}

	// Send the custom message
	if err := r.sendSlackMessage(ctx, notifier.Spec.SlackWebhookUrl, message); err != nil {
		notifier.Status.NotificationsFailed++
		notifier.Status.LastError = err.Error()
		logger.Error(err, "Failed to send custom message")
	} else {
		notifier.Status.NotificationsSent++
		now := metav1.NewTime(time.Now())
		notifier.Status.LastSentNotification = &now
		notifier.Status.LastError = ""
		logger.Info("Custom message sent successfully")
	}

	// Update status
	if err := r.Status().Update(ctx, &notifier); err != nil {
		logger.Error(err, "Failed to update notifier status")
	}

	return nil
}

// sendSlackMessage sends a message to Slack webhook
func (r *ClusterPolicyNotifierReconciler) sendSlackMessage(ctx context.Context, webhookURL, message string) error {
	// Create simple Slack message payload
	payload := SlackMessage{
		Text: message,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack message: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "K8lex-Policy-Operator/1.0")

	// Send request
	client := r.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Slack webhook returned status: %d", resp.StatusCode)
	}

	return nil
}

// updateStatus updates the notifier status
func (r *ClusterPolicyNotifierReconciler) updateStatus(ctx context.Context, notifier *policyv1alpha1.ClusterPolicyNotifier, phase policyv1alpha1.NotifierPhase, errorMsg string) (ctrl.Result, error) {
	notifier.Status.Phase = phase
	notifier.Status.LastError = errorMsg
	notifier.Status.ObservedGeneration = notifier.Generation

	// Update conditions
	now := metav1.NewTime(time.Now())
	readyCondition := policyv1alpha1.NotifierCondition{
		Type:               policyv1alpha1.NotifierConditionReady,
		LastUpdateTime:     now,
		LastTransitionTime: now,
	}

	configuredCondition := policyv1alpha1.NotifierCondition{
		Type:               policyv1alpha1.NotifierConditionConfigured,
		LastUpdateTime:     now,
		LastTransitionTime: now,
	}

	switch phase {
	case policyv1alpha1.NotifierPhaseReady:
		readyCondition.Status = metav1.ConditionTrue
		readyCondition.Reason = "Ready"
		readyCondition.Message = "Notifier is ready and webhook test successful"

		configuredCondition.Status = metav1.ConditionTrue
		configuredCondition.Reason = "Configured"
		configuredCondition.Message = "Notifier is properly configured"

	case policyv1alpha1.NotifierPhaseError:
		readyCondition.Status = metav1.ConditionFalse
		readyCondition.Reason = "ConfigurationError"
		readyCondition.Message = errorMsg

		configuredCondition.Status = metav1.ConditionFalse
		configuredCondition.Reason = "ConfigurationError"
		configuredCondition.Message = errorMsg
	}

	// Update conditions
	notifier.Status.Conditions = r.updateConditions(notifier.Status.Conditions, readyCondition)
	notifier.Status.Conditions = r.updateConditions(notifier.Status.Conditions, configuredCondition)

	if err := r.Status().Update(ctx, notifier); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update status: %w", err)
	}

	// Requeue if there's an error
	if phase == policyv1alpha1.NotifierPhaseError {
		return ctrl.Result{RequeueAfter: time.Minute * 5}, nil
	}

	return ctrl.Result{}, nil
}

// updateConditions updates or adds a condition to the conditions slice
func (r *ClusterPolicyNotifierReconciler) updateConditions(conditions []policyv1alpha1.NotifierCondition, newCondition policyv1alpha1.NotifierCondition) []policyv1alpha1.NotifierCondition {
	for i, condition := range conditions {
		if condition.Type == newCondition.Type {
			// Update existing condition
			if condition.Status != newCondition.Status {
				newCondition.LastTransitionTime = newCondition.LastUpdateTime
			} else {
				newCondition.LastTransitionTime = condition.LastTransitionTime
			}
			conditions[i] = newCondition
			return conditions
		}
	}

	// Add new condition
	return append(conditions, newCondition)
}

// SetupWithManager sets up the controller with the Manager
func (r *ClusterPolicyNotifierReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Log = mgr.GetLogger().WithName("notifier-controller")

	// Initialize HTTPClient if not already set
	if r.HTTPClient == nil {
		r.HTTPClient = &http.Client{
			Timeout: 30 * time.Second,
		}
	}

	r.Log.Info("Setting up simple ClusterPolicyNotifier controller")

	return ctrl.NewControllerManagedBy(mgr).
		For(&policyv1alpha1.ClusterPolicyNotifier{}).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 3,
			LogConstructor: func(request *reconcile.Request) logr.Logger {
				if request == nil {
					return mgr.GetLogger().WithName("notifier-controller")
				}
				return mgr.GetLogger().WithName("notifier-controller").WithValues(
					"notifier", request.Name,
					"namespace", request.Namespace,
				)
			},
		}).
		Complete(r)
}
