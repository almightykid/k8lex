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
	"regexp"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ClusterPolicyNotifierSpec defines the desired state of ClusterPolicyNotifier
type ClusterPolicyNotifierSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	Slack *SlackConfig `json:"slack,omitempty"`
	Teams *TeamsConfig `json:"teams,omitempty"`
	Email *EmailConfig `json:"email,omitempty"`
}

type SlackConfig struct {
	WebhookURL string `json:"webhookUrl"` // Webhook de Slack para enviar mensajes
	Channel    string `json:"channel"`    // Canal de Slack donde se enviarán las alertas
}

type TeamsConfig struct {
	WebhookURL string `json:"webhookUrl"` // Webhook de Teams
}

type EmailConfig struct {
	SMTPServer   string   `json:"smtpServer"`
	SMTPPort     int      `json:"smtpPort"`
	FromEmail    string   `json:"fromEmail"`
	Recipients   []string `json:"toEmail"`
	AuthUser     string   `json:"authUser"`
	AuthPassword string   `json:"authPassword"`
}

func ValidateEmail(email string) bool {
	// Basic regular expression to validate emails.
	// This is a simple validation; you can use more robust libraries if needed.
	regex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(regex)
	return re.MatchString(email)
}

func (c *ClusterPolicyNotifier) Validate() error {
	if c.Spec.Email != nil {
		// Validate FromEmail
		if !ValidateEmail(c.Spec.Email.FromEmail) {
			return errors.New("invalid FromEmail address")
		}

		// Validate each recipient email
		for _, recipient := range c.Spec.Email.Recipients {
			if !ValidateEmail(recipient) {
				return errors.New("invalid recipient email: " + recipient)
			}
		}
	}
	return nil
}

// ClusterPolicyNotifierStatus defines the observed state of ClusterPolicyNotifier
type ClusterPolicyNotifierStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	LastSentNotification metav1.Time `json:"lastSentNotification,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

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
