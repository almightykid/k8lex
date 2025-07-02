package clusterpolicyvalidator

import (
	"context"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	defaultNotifier = "slack-notifier"
)

// SendPolicyViolationNotification sends a notification when a resource violates a policy rule.
// It includes details about the resource, the violated rule, and the reason for the violation.
func (r *ClusterPolicyValidatorReconciler) SendPolicyViolationNotification(ctx context.Context, resourceName, ruleName, reason, action string) error {
	logger := log.FromContext(ctx)

	if r.NotifierController == nil {
		logger.Info("NotifierController not configured, skipping notification")
		return nil
	}

	var message string
	switch action {
	case "warn":
		message = fmt.Sprintf("⚠️ Policy violation detected for resource %s (Rule: %s): %s",
			resourceName, ruleName, reason)
	case "block":
		message = fmt.Sprintf("⛔ Blocking resource %s due to violation of rule %s\n\nReason: %s",
			resourceName, ruleName, reason)
	default:
		message = fmt.Sprintf("Policy violation detected for resource %s (Rule: %s): %s",
			resourceName, ruleName, reason)
	}

	logger.Info("Sending policy violation notification",
		"resource", resourceName,
		"rule", ruleName,
		"message", message)

	if err := r.NotifierController.SendMessage(ctx, defaultNotifier, message); err != nil {
		logger.Error(err, "Failed to send policy violation notification")
		return fmt.Errorf("failed to send notification: %w", err)
	}
	return nil
}

// SendCustomNotification sends a custom notification using the specified notifier.
// This is a generic method that can be used for any type of notification.
func (r *ClusterPolicyValidatorReconciler) SendCustomNotification(ctx context.Context, notifierName, message string) error {
	logger := log.FromContext(ctx)

	if r.NotifierController == nil {
		logger.Info("NotifierController not configured, skipping notification")
		return nil
	}

	logger.Info("Sending custom notification",
		"notifier", notifierName,
		"message", message)

	if err := r.NotifierController.SendMessage(ctx, notifierName, message); err != nil {
		logger.Error(err, "Failed to send custom notification")
		return fmt.Errorf("failed to send notification: %w", err)
	}
	return nil
}

// NotifyResourceBlocked sends a notification when a resource is blocked due to policy violation.
// It includes comprehensive information about the blocked resource, including its kind,
// name, the violated rule, and the reason for blocking.
func (r *ClusterPolicyValidatorReconciler) NotifyResourceBlocked(ctx context.Context, resourceName, resourceKind, ruleName, reason string) error {
	fullResourceName := fmt.Sprintf("%s/%s", resourceKind, resourceName)
	message := fmt.Sprintf("Blocking resource %s due to violation of rule %s\n\n📋 Reason: %s\n🕐 Timestamp: %s",
		fullResourceName, ruleName, reason, time.Now().Format(time.RFC3339))

	return r.SendCustomNotification(ctx, defaultNotifier, message)
}

// NotifyValidationSuccess sends a notification for successful validation of a resource.
// This is typically used to confirm that a resource has passed all policy checks.
func (r *ClusterPolicyValidatorReconciler) NotifyValidationSuccess(ctx context.Context, message string) error {
	successMessage := fmt.Sprintf("✅ %s", message)
	return r.SendCustomNotification(ctx, defaultNotifier, successMessage)
}

// NotifyWarning sends a warning notification.
// This is used for non-blocking issues that should be brought to attention.
func (r *ClusterPolicyValidatorReconciler) NotifyWarning(ctx context.Context, message string) error {
	warningMessage := fmt.Sprintf("⚠️ %s", message)
	return r.SendCustomNotification(ctx, defaultNotifier, warningMessage)
}
