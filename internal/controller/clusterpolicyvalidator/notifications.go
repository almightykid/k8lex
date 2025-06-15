package clusterpolicyvalidator

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ✅ Método simple para enviar notificación de violación
func (r *ClusterPolicyValidatorReconciler) SendPolicyViolationNotification(ctx context.Context, resourceName, ruleName, reason string) error {
	logger := log.FromContext(ctx)

	if r.NotifierController == nil {
		logger.Info("NotifierController not configured, skipping notification")
		return nil
	}

	// ✅ Crear mensaje simple según tu formato
	message := fmt.Sprintf("🚨 Bloqueando recurso %s porque incumple con la regla %s\n\nMotivo: %s",
		resourceName, ruleName, reason)

	logger.Info("Sending policy violation notification",
		"resource", resourceName,
		"rule", ruleName,
		"message", message)

	// ✅ Enviar usando el notifier controller simple
	// Usamos "slack-notifier" como nombre predeterminado según tu ejemplo
	return r.NotifierController.SendMessage(ctx, "slack-notifier", message)
}

// ✅ Método para enviar notificación personalizada
func (r *ClusterPolicyValidatorReconciler) SendCustomNotification(ctx context.Context, notifierName, message string) error {
	logger := log.FromContext(ctx)

	logger.Info("Sending custom notification",
		"notifier", notifierName,
		"message", message)

	if r.NotifierController == nil {
		logger.Info("NotifierController not configured, skipping notification")
		return nil
	}

	logger.Info("Sending custom notification",
		"notifier", notifierName,
		"message", message)

	return r.NotifierController.SendMessage(ctx, notifierName, message)
}

// ✅ Método para notificar bloqueo de recurso
func (r *ClusterPolicyValidatorReconciler) NotifyResourceBlocked(ctx context.Context, resourceName, resourceKind, ruleName, reason string) error {
	fullResourceName := fmt.Sprintf("%s/%s", resourceKind, resourceName)
	message := fmt.Sprintf("🚫 Bloqueando recurso %s porque incumple con la regla %s\n\n📋 Motivo: %s\n🕐 Timestamp: %s",
		fullResourceName, ruleName, reason, ctx.Value("timestamp"))

	return r.SendCustomNotification(ctx, "slack-notifier", message)
}

// ✅ Método para notificar éxito en validación
func (r *ClusterPolicyValidatorReconciler) NotifyValidationSuccess(ctx context.Context, message string) error {
	successMessage := fmt.Sprintf("✅ %s", message)
	return r.SendCustomNotification(ctx, "slack-notifier", successMessage)
}

// ✅ Método para notificar warning
func (r *ClusterPolicyValidatorReconciler) NotifyWarning(ctx context.Context, message string) error {
	warningMessage := fmt.Sprintf("⚠️ %s", message)
	return r.SendCustomNotification(ctx, "slack-notifier", warningMessage)
}
