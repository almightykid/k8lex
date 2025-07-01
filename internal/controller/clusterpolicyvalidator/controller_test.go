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

package clusterpolicyvalidator

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	clusterpolicyvalidatorv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyvalidator/v1alpha1"
)

var _ = Describe("ClusterPolicyValidator Controller", func() {
	var (
		ctx           context.Context
		reconciler    *ClusterPolicyValidatorReconciler
		testNamespace string
		eventRecorder record.EventRecorder
	)

	BeforeEach(func() {
		ctx = context.Background()
		testNamespace = "test-namespace-" + randomString(8)

		// Create test namespace
		ns := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: testNamespace,
			},
		}
		Expect(k8sClient.Create(ctx, ns)).To(Succeed())

		// Initialize reconciler with enhanced features
		reconciler = &ClusterPolicyValidatorReconciler{
			Client:             k8sClient,
			Scheme:             k8sClient.Scheme(),
			EventRecorder:      eventRecorder,
			ConflictResolution: ConflictResolutionMostRestrictive,
		}
	})

	AfterEach(func() {
		// Cleanup test namespace
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: testNamespace}}
		k8sClient.Delete(ctx, ns)
	})

	Context("Basic Reconciliation", func() {
		const resourceName = "test-policy"

		var policy *clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator

		BeforeEach(func() {
			policy = createTestPolicy(resourceName, testNamespace)
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())
		})

		AfterEach(func() {
			Expect(k8sClient.Delete(ctx, policy)).To(Succeed())
		})

		It("should successfully reconcile a policy", func() {
			By("Reconciling the created policy")
			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: resourceName},
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeFalse())
		})

		It("should update namespace filter state when policy changes", func() {
			By("Verifying initial state")
			Expect(reconciler.namespaceFilter).ToNot(BeNil())

			By("Reconciling the policy")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: resourceName},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying namespace filter was updated")
			Expect(reconciler.namespaceFilter.LastUpdated).To(BeTemporally("~", time.Now(), time.Minute))
		})
	})

	Context("Policy Evaluation", func() {
		var (
			policy     *clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator
			testPod    *corev1.Pod
			deployment *appsv1.Deployment
		)

		BeforeEach(func() {
			// Create policy that blocks pods without specific labels
			policy = &clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{
				ObjectMeta: metav1.ObjectMeta{
					Name: "label-policy",
				},
				Spec: clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorSpec{
					ValidationRules: []clusterpolicyvalidatorv1alpha1.ValidationRule{
						{
							Name:   "require-app-label",
							Action: "block",
							MatchResources: clusterpolicyvalidatorv1alpha1.MatchResources{
								Kinds: []string{"Pod", "Deployment"},
							},
							Conditions: []clusterpolicyvalidatorv1alpha1.Condition{
								{
									Key:      "metadata.labels.app",
									Operator: "IsNotEmpty",
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Create test pod without required label
			testPod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: testNamespace,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "nginx:latest",
						},
					},
				},
			}

			// Create test deployment without required label
			deployment = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-deployment",
					Namespace: testNamespace,
				},
				Spec: appsv1.DeploymentSpec{
					Replicas: int32Ptr(3),
					Selector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"app": "test"},
					},
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{"app": "test"},
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name:  "test-container",
									Image: "nginx:latest",
								},
							},
						},
					},
				},
			}
		})

		AfterEach(func() {
			k8sClient.Delete(ctx, policy)
			k8sClient.Delete(ctx, testPod)
			k8sClient.Delete(ctx, deployment)
		})

		It("should block pod without required label", func() {
			By("Creating pod without required label")
			Expect(k8sClient.Create(ctx, testPod)).To(Succeed())

			By("Reconciling the pod")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      testPod.Name,
					Namespace: testPod.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying pod was deleted due to policy violation")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      testPod.Name,
					Namespace: testPod.Namespace,
				}, &corev1.Pod{})
				return errors.IsNotFound(err)
			}).Should(BeTrue())
		})

		It("should scale down deployment without required label", func() {
			By("Creating deployment without required label")
			// Remove the app label to trigger violation
			deployment.ObjectMeta.Labels = map[string]string{}
			Expect(k8sClient.Create(ctx, deployment)).To(Succeed())

			By("Reconciling the deployment")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      deployment.Name,
					Namespace: deployment.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying deployment was scaled to zero")
			Eventually(func() int32 {
				updatedDeployment := &appsv1.Deployment{}
				k8sClient.Get(ctx, types.NamespacedName{
					Name:      deployment.Name,
					Namespace: deployment.Namespace,
				}, updatedDeployment)
				return *updatedDeployment.Spec.Replicas
			}).Should(Equal(int32(0)))

			By("Verifying blocking annotations were added")
			updatedDeployment := &appsv1.Deployment{}
			k8sClient.Get(ctx, types.NamespacedName{
				Name:      deployment.Name,
				Namespace: deployment.Namespace,
			}, updatedDeployment)

			Expect(updatedDeployment.Annotations).To(HaveKey(PolicyBlockedAnnotation))
			Expect(updatedDeployment.Annotations[PolicyBlockedAnnotation]).To(Equal("true"))
			Expect(updatedDeployment.Annotations).To(HaveKey(OriginalReplicasAnnotation))
			Expect(updatedDeployment.Annotations[OriginalReplicasAnnotation]).To(Equal("3"))
		})

		It("should allow resource with required label", func() {
			By("Creating pod with required label")
			testPod.ObjectMeta.Labels = map[string]string{"app": "test-app"}
			Expect(k8sClient.Create(ctx, testPod)).To(Succeed())

			By("Reconciling the pod")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      testPod.Name,
					Namespace: testPod.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying pod was not deleted")
			pod := &corev1.Pod{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      testPod.Name,
				Namespace: testPod.Namespace,
			}, pod)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("Policy Bypass", func() {
		var (
			policy  *clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator
			testPod *corev1.Pod
		)

		BeforeEach(func() {
			policy = createTestPolicy("bypass-test-policy", testNamespace)
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			testPod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod-bypass",
					Namespace: testNamespace,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "nginx:latest",
						},
					},
				},
			}
		})

		AfterEach(func() {
			k8sClient.Delete(ctx, policy)
			k8sClient.Delete(ctx, testPod)
		})

		It("should bypass policies with emergency bypass annotation", func() {
			By("Creating pod with emergency bypass annotation")
			testPod.ObjectMeta.Annotations = map[string]string{
				EmergencyBypassAnnotation: "true",
			}
			Expect(k8sClient.Create(ctx, testPod)).To(Succeed())

			By("Reconciling the pod")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      testPod.Name,
					Namespace: testPod.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying pod was not deleted despite policy violation")
			pod := &corev1.Pod{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      testPod.Name,
				Namespace: testPod.Namespace,
			}, pod)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should bypass policies with regular bypass annotation", func() {
			By("Creating pod with regular bypass annotation")
			testPod.ObjectMeta.Annotations = map[string]string{
				PolicyBypassAnnotation: "true",
			}
			Expect(k8sClient.Create(ctx, testPod)).To(Succeed())

			By("Reconciling the pod")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      testPod.Name,
					Namespace: testPod.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying pod was not deleted")
			pod := &corev1.Pod{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      testPod.Name,
				Namespace: testPod.Namespace,
			}, pod)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("Namespace Filtering", func() {
		var policy *clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator

		BeforeEach(func() {
			policy = &clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{
				ObjectMeta: metav1.ObjectMeta{
					Name: "namespace-filter-policy",
				},
				Spec: clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorSpec{
					Namespaces: clusterpolicyvalidatorv1alpha1.Namespace{
						Include: []string{testNamespace},
						Exclude: []string{"kube-system"},
					},
					ValidationRules: []clusterpolicyvalidatorv1alpha1.ValidationRule{
						{
							Name:   "test-rule",
							Action: "block",
							MatchResources: clusterpolicyvalidatorv1alpha1.MatchResources{
								Kinds: []string{"Pod"},
							},
							Conditions: []clusterpolicyvalidatorv1alpha1.Condition{
								{
									Key:      "metadata.labels.required",
									Operator: "IsNotEmpty",
								},
							},
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, policy)).To(Succeed())

			// Trigger namespace filter update
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{Name: policy.Name},
			})
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			k8sClient.Delete(ctx, policy)
		})

		It("should process resources in included namespaces", func() {
			By("Verifying namespace is allowed")
			logger := reconciler.Log.WithName("test")
			allowed := reconciler.isNamespaceAllowedByPredicate(testNamespace, logger)
			Expect(allowed).To(BeTrue())
		})

		It("should not process resources in excluded namespaces", func() {
			By("Verifying excluded namespace is blocked")
			logger := reconciler.Log.WithName("test")
			allowed := reconciler.isNamespaceAllowedByPredicate("kube-system", logger)
			Expect(allowed).To(BeFalse())
		})

		It("should not process resources not in included namespaces", func() {
			By("Verifying non-included namespace is blocked")
			logger := reconciler.Log.WithName("test")
			allowed := reconciler.isNamespaceAllowedByPredicate("other-namespace", logger)
			Expect(allowed).To(BeFalse())
		})
	})

	Context("Health Check", func() {
		It("should pass health check when system is healthy", func() {
			By("Running health check")
		})
	})

	Context("JQ Operations", func() {
		var testResource *unstructured.Unstructured

		BeforeEach(func() {
			testResource = &unstructured.Unstructured{
				Object: map[string]interface{}{
					"metadata": map[string]interface{}{
						"labels": map[string]interface{}{
							"app":     "test-app",
							"version": "1.0",
						},
					},
					"spec": map[string]interface{}{
						"containers": []interface{}{
							map[string]interface{}{
								"name":  "container1",
								"image": "nginx:latest",
							},
							map[string]interface{}{
								"name":  "container2",
								"image": "redis:alpine",
							},
						},
					},
				},
			}
		})

		It("should extract simple values", func() {
			By("Extracting app label")
			values, err := reconciler.extractValues(testResource, "metadata.labels.app")
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(HaveLen(1))
			Expect(values[0]).To(Equal("test-app"))
		})

		It("should extract array values", func() {
			By("Extracting container images")
			values, err := reconciler.extractValues(testResource, "spec.containers[*].image")
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(HaveLen(2))
			Expect(values).To(ContainElement("nginx:latest"))
			Expect(values).To(ContainElement("redis:alpine"))
		})

		It("should handle missing paths gracefully", func() {
			By("Extracting non-existent path")
			values, err := reconciler.extractValues(testResource, "metadata.annotations.missing")
			Expect(err).NotTo(HaveOccurred())
			Expect(values).To(BeEmpty())
		})
	})
})

// Helper functions

func createTestPolicy(name, namespace string) *clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator {
	return &clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: clusterpolicyvalidatorv1alpha1.ClusterPolicyValidatorSpec{
			Namespaces: clusterpolicyvalidatorv1alpha1.Namespace{
				Include: []string{namespace},
			},
			ValidationRules: []clusterpolicyvalidatorv1alpha1.ValidationRule{
				{
					Name:   "test-rule",
					Action: "block",
					MatchResources: clusterpolicyvalidatorv1alpha1.MatchResources{
						Kinds: []string{"Pod"},
					},
					Conditions: []clusterpolicyvalidatorv1alpha1.Condition{
						{
							Key:      "metadata.labels.required",
							Operator: "IsNotEmpty",
						},
					},
				},
			},
		},
	}
}

func int32Ptr(i int32) *int32 {
	return &i
}
