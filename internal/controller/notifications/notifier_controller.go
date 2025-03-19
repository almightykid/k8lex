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

package notifications

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"gopkg.in/gomail.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	notificationsv1alpha1 "github.com/almightykid/k8lex/api/notifications/v1alpha1"
)

// NotifierReconciler reconciles a Notifier object
type NotifierReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=notifications.k8lex.io,resources=notifiers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=notifications.k8lex.io,resources=notifiers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=notifications.k8lex.io,resources=notifiers/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Notifier object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/reconcile
func (r *NotifierReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	// Fetch the necessary secret data
	secretName := "k8lex-notifier-configuration"
	namespace := req.Namespace
	keys := []string{"slackWebhookURL", "teamsWebhookURL", "email", "password", "recipients"}
	secretData, err := getSecretData(ctx, r, secretName, namespace, keys)
	if err != nil {
		return ctrl.Result{}, err
	}

	// Define the notification message dynamically (could be rule-based)
	message := "This is a test notification for rule XYZ."

	// Send notifications
	if slackWebhookURL, exists := secretData["slackWebhookURL"]; exists {
		// Send Slack notification
		err = sendNotification(slackWebhookURL, message)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to send Slack notification: %w", err)
		}
	}

	if teamsWebhookURL, exists := secretData["teamsWebhookURL"]; exists {
		// Send Teams notification
		err = sendNotification(teamsWebhookURL, message)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to send Teams notification: %w", err)
		}
	}

	if email, exists := secretData["email"]; exists {
		// Send email notification
		emailConfig := map[string]string{
			"email":      email,
			"password":   secretData["password"],
			"recipients": secretData["recipients"],
		}
		err = sendEmail(emailConfig, "Notification Subject", message)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to send email: %w", err)
		}
	}

	return ctrl.Result{}, nil
}

func getSecretData(ctx context.Context, r *NotifierReconciler, secretName, namespace string, keys []string) (map[string]string, error) {
	// Get the Secret from the Kubernetes cluster
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      secretName,
		Namespace: namespace,
	}, secret)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s: %w", secretName, err)
	}

	// Prepare a map to hold the secret data
	secretData := make(map[string]string)

	// Loop through the keys and extract the corresponding secret values
	for _, key := range keys {
		value, exists := secret.Data[key]
		if !exists {
			return nil, fmt.Errorf("key %s not found in secret %s", key, secretName)
		}
		secretData[key] = string(value)
	}

	return secretData, nil
}

// Send Notification to webhook function
func sendNotification(webhookURL, message string) error {
	// Prepare the payload for Slack/Teams
	payload := map[string]string{"text": message}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Log.Error(err, "Error marshaling message")
		return fmt.Errorf("error marshaling message: %w", err)
	}

	// Log the sending request
	log.Log.Info("Sending notification", "webhookURL", webhookURL, "message", message)

	// Send the HTTP request to the webhook URL
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Log.Error(err, "Error sending notification to webhook")
		return fmt.Errorf("error sending notification: %w", err)
	}
	defer resp.Body.Close()

	// Log the response status
	log.Log.Info("Notification sent successfully", "statusCode", resp.StatusCode)

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		log.Log.Error(fmt.Errorf("status code %d", resp.StatusCode), "Error sending notification")
		return fmt.Errorf("error sending notification, status code: %d", resp.StatusCode)
	}

	return nil
}

// Send Mail function
func sendEmail(emailConfig map[string]string, subject, body string) error {
	// Extract the email configuration
	from := emailConfig["email-username"]
	password := emailConfig["email-password"]
	to := emailConfig["email-recipients"]

	// If there are multiple recipients, split the list by comma
	recipients := strings.Split(to, ",")

	// Set up the email message
	mail := gomail.NewMessage()
	mail.SetHeader("From", from)
	mail.SetHeader("To", recipients...)
	mail.SetHeader("Subject", subject)
	mail.SetBody("text/plain", body)

	// Set up the SMTP server
	dialer := gomail.NewDialer("smtp.gmail.com", 587, from, password)

	// Send the email
	err := dialer.DialAndSend(mail)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *NotifierReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&notificationsv1alpha1.Notifier{}).
		Complete(r)
}
