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

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ClusterPolicyUpdater is the Schema for the clusterpolicyupdaters API
type ClusterPolicyUpdater struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ClusterPolicyUpdaterSpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterPolicyUpdaterList contains a list of ClusterPolicyUpdater
type ClusterPolicyUpdaterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClusterPolicyUpdater `json:"items"`
}

type ClusterPolicyUpdaterSpec struct {
	Description  string        `json:"description,omitempty"`
	UpdaterRules []UpdaterRule `json:"updaterRules,omitempty"`
}

type UpdaterRule struct {
	Name         string       `json:"name"`
	Description  string       `json:"description,omitempty"`
	Update       []Update     `json:"update,omitempty"`
	Notification Notification `json:"notification,omitempty"`
}

type Update struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Notification struct {
	Enabled     bool   `json:"enabled,omitempty"`
	Message     string `json:"message,omitempty"`
	NotifierRef Ref    `json:"notifierRef,omitempty"`
}

type Ref struct {
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

func init() {
	SchemeBuilder.Register(&ClusterPolicyUpdater{}, &ClusterPolicyUpdaterList{})
}
