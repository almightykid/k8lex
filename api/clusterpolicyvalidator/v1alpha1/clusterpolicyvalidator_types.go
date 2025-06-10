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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ClusterPolicyValidatorSpec defines the desired state of ClusterPolicyValidator
type ClusterPolicyValidatorSpec struct {
	Description     string           `json:"description,omitempty"`     // Description of the cluster policy validator
	Namespaces      Namespace        `json:"namespaces,omitempty"`      // List of namespaces to exclude from validation
	ValidationRules []ValidationRule `json:"validationRules,omitempty"` // List of validation rules
	Notification    Notification     `json:"notification,omitempty"`    // Notification configuration
}

type Namespace struct {
	Exclude []string `json:"exclude,omitempty"` // List of namespaces to exclude from validation
	Include []string `json:"include,omitempty"` // List of namespaces to include in validation
}

type Notification struct {
	Enabled     bool `json:"enabled,omitempty"`     // If notifications are enabled
	NotifierRef Ref  `json:"notifierRef,omitempty"` // Reference to the notifier (e.g., Slack, email)
}

type Ref struct {
	Name      string `json:"name,omitempty"`      // Name of the notifier
	Namespace string `json:"namespace,omitempty"` // Namespace of the notifier
}

type ValidationRule struct {
	Name              string            `json:"name"`                  // Name of the validation rule
	Description       string            `json:"description,omitempty"` // Optional description of the rule
	Severity          string            `json:"severity,omitempty"`    // Severity of the validation
	ErrorMessage      string            `json:"errorMessage"`
	MatchResources    MatchResources    `json:"matchResources"`              // Resources to which this rule applies
	Conditions        []Condition       `json:"conditions"`                  // Conditions for rule matching
	Action            string            `json:"action,omitempty"`            // Action to take when the rule matches
	NamespaceSelector NamespaceSelector `json:"namespaceSelector,omitempty"` // Namespace selector for the rule
	LabelSelector     LabelSelector     `json:"labelSelector,omitempty"`     // Label selector for the rule
}

type NamespaceSelector struct {
	MatchNamespaces []string `json:"matchNamespaces,omitempty"` // List of namespaces to match
}
type LabelSelector struct {
	MatchLabels []string `json:"matchLabels,omitempty"` // List of labels to match
}

type MatchResources struct {
	Kinds []string `json:"kinds"` // List of resource kinds to match
}

type Condition struct {
	Key      string   `json:"key"`      // Key for the condition
	Operator string   `json:"operator"` // Operator used for matching
	Values   []string `json:"values"`   // Values to match against
}

// ClusterPolicyValidatorStatus defines the observed state of ClusterPolicyValidator
type ClusterPolicyValidatorStatus struct {
	// Status of the validation process: can be "Valid", "Invalid", "Pending", etc.
	ValidationStatus string `json:"validationStatus,omitempty"`

	// Timestamp of the last validation run
	LastValidationTime *metav1.Time `json:"lastValidationTime,omitempty"`

	// List of errors encountered during validation, if any
	ValidationErrors []string `json:"validationErrors,omitempty"`

	// Status of the notification system (e.g., whether notifications have been sent successfully)
	NotifierStatus string `json:"notifierStatus,omitempty"`

	// Overall status of the resource (Pending, Valid, Invalid)
	OverallStatus string `json:"overallStatus,omitempty"`

	// Optional field to store the number of successfully validated resources (if applicable)
	ValidatedResourcesCount int `json:"validatedResourcesCount,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ClusterPolicyValidator is the Schema for the clusterpolicyvalidators API
type ClusterPolicyValidator struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClusterPolicyValidatorSpec   `json:"spec,omitempty"`
	Status ClusterPolicyValidatorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterPolicyValidatorList contains a list of ClusterPolicyValidator
type ClusterPolicyValidatorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterPolicyValidator `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ClusterPolicyValidator{}, &ClusterPolicyValidatorList{})
}
