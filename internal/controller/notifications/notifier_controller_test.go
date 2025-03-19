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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	// Import controller package
	. "github.com/almightykid/k8lex/internal/controller/notifications"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	notificationsv1alpha1 "github.com/almightykid/k8lex/api/notifications/v1alpha1"
)

var _ = Describe("Notifier Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		notifier := &notificationsv1alpha1.Notifier{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind Notifier")
			err := k8sClient.Get(ctx, typeNamespacedName, notifier)
			if err != nil && errors.IsNotFound(err) {
				resource := &notificationsv1alpha1.Notifier{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					// TODO(user): Specify other spec details if needed.
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &notificationsv1alpha1.Notifier{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance Notifier")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &NotifierReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// TODO(user): Add more specific assertions depending on your controller's reconciliation logic.
			// Example: If you expect a certain status condition after reconciliation, verify it here.
		})
	})
})

func TestSendNotification(t *testing.T) {
	// Step 1: Create a mock HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Step 2: Check that it's a POST request
		assert.Equal(t, "POST", r.Method)

		// Check that the body of the request contains the expected message
		var body []byte
		_, err := r.Body.Read(body)
		if err != nil {
			t.Fatalf("Error reading request body: %v", err)
		}

		// Assert that the body contains the expected message (you can use any matching criteria here)
		assert.Contains(t, string(body), "Test message")

		// Respond with 200 OK to simulate successful processing of the request
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close() // Ensure the server is closed after the test

	// Step 3: Call the sendNotification function directly with the mock server URL
	webhookURL := ts.URL // This is the URL of the mock server
	message := "Test message"
	err := notifications.SendNotification(webhookURL, message)

	// Step 4: Assert no error was returned
	assert.NoError(t, err)

	// Optional: You can also log the success for debugging
	fmt.Println("Notification sent successfully!")
}
