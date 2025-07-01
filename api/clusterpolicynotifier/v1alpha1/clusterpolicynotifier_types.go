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

package v1alpha1

import (
	"errors"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterPolicyNotifierSpec defines the desired state of ClusterPolicyNotifier
type ClusterPolicyNotifierSpec struct {
	// Slack webhook URL for sending notifications
	// +kubebuilder:validation:Required
	SlackWebhookUrl string `json:"slackWebhookUrl"`
}

// ClusterPolicyNotifierStatus defines the observed state of ClusterPolicyNotifier
type ClusterPolicyNotifierStatus struct {
	// Observed generation (to prevent duplicate processing)
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Timestamp of the last sent notification
	// +optional
	LastSentNotification *metav1.Time `json:"lastSentNotification,omitempty"`

	// Total number of notifications sent
	// +optional
	NotificationsSent int64 `json:"notificationsSent,omitempty"`

	// Number of failed notification attempts
	// +optional
	NotificationsFailed int64 `json:"notificationsFailed,omitempty"`

	// Last error message if notification failed
	// +optional
	LastError string `json:"lastError,omitempty"`

	// Current status of the notifier
	// +optional
	Phase NotifierPhase `json:"phase,omitempty"`

	// Human-readable conditions about the notifier
	// +optional
	Conditions []NotifierCondition `json:"conditions,omitempty"`
}

// NotifierPhase represents the current phase of the notifier
type NotifierPhase string

const (
	// NotifierPhaseReady indicates the notifier is ready to send notifications
	NotifierPhaseReady NotifierPhase = "Ready"

	// NotifierPhaseError indicates the notifier has configuration errors
	NotifierPhaseError NotifierPhase = "Error"
)

// NotifierCondition represents a condition of the notifier
type NotifierCondition struct {
	// Type of the condition
	Type NotifierConditionType `json:"type"`

	// Status of the condition
	Status metav1.ConditionStatus `json:"status"`

	// Last time the condition was updated
	LastUpdateTime metav1.Time `json:"lastUpdateTime"`

	// Last time the condition transitioned from one status to another
	LastTransitionTime metav1.Time `json:"lastTransitionTime"`

	// Reason for the condition's last transition
	Reason string `json:"reason"`

	// Human-readable message indicating details about the transition
	Message string `json:"message"`
}

// NotifierConditionType represents the type of notifier condition
type NotifierConditionType string

const (
	// NotifierConditionReady indicates whether the notifier is ready
	NotifierConditionReady NotifierConditionType = "Ready"

	// NotifierConditionConfigured indicates whether the notifier is properly configured
	NotifierConditionConfigured NotifierConditionType = "Configured"
)

// ValidateWebhookURL validates a Slack webhook URL
func ValidateWebhookURL(url string) bool {
	if url == "" {
		return false
	}
	// Slack webhook URLs must start with https://hooks.slack.com/
	return strings.HasPrefix(url, "https://hooks.slack.com/")
}

// Validate validates the ClusterPolicyNotifier configuration
func (c *ClusterPolicyNotifier) Validate() error {
	// Validate Slack webhook URL

	if !ValidateWebhookURL(c.Spec.SlackWebhookUrl) {
		return errors.New("invalid Slack webhook URL: must start with https://hooks.slack.com/")
	}

	return nil
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="Notifications Sent",type="integer",JSONPath=".status.notificationsSent"
// +kubebuilder:printcolumn:name="Last Sent",type="date",JSONPath=".status.lastSentNotification"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ClusterPolicyNotifier is the Schema for the clusterpolicynotifiers API
type ClusterPolicyNotifier struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterPolicyNotifierSpec   `json:"spec,omitempty"`
	Status ClusterPolicyNotifierStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterPolicyNotifierList contains a list of ClusterPolicyNotifier
type ClusterPolicyNotifierList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterPolicyNotifier `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterPolicyNotifier{}, &ClusterPolicyNotifierList{})
}
