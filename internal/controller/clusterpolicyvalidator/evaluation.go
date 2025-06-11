package clusterpolicyvalidator

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	clusterpolicyvalidatorv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyvalidator/v1alpha1"
	"github.com/go-logr/logr"
	"github.com/itchyny/gojq"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// evaluatePolicies orchestrates the policy evaluation process for a given Kubernetes resource.
// It incorporates caching, circuit breaking, concurrency limiting, and failure handling
// to ensure efficient and resilient policy enforcement.
// It returns a list of ValidationResult indicating any policy violations found.
func (r *ClusterPolicyValidatorReconciler) evaluatePolicies(
	ctx context.Context,
	resource *unstructured.Unstructured, // The unstructured representation of the resource being evaluated.
	foundResource client.Object, // The typed client.Object for direct Kubernetes API interaction (if needed).
	resourceGVK schema.GroupVersionKind, // GroupVersionKind of the resource.
	policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator, // List of policies to evaluate against the resource.
	logger logr.Logger, // Logger instance for structured logging.
) []ValidationResult {
	// Step 1: Check for policy bypass annotations.
	// If the resource has a bypass annotation, no policies are evaluated.
	if r.shouldBypassPolicies(foundResource) {
		logger.V(1).Info("Policy evaluation bypassed for resource", "resource", resource.GetName(), "kind", resourceGVK.Kind)
		return []ValidationResult{}
	}

	// Step 2: Generate a cache key for the resource and the policies that apply to it.
	// This key is used to check and store policy evaluation results.
	cacheKey := r.generatePolicyEvalCacheKey(resource, policies)

	// Step 3: Attempt to retrieve evaluation results from the policy evaluation cache.
	if r.policyEvalCache != nil {
		if cached, found := r.policyEvalCache.Get(cacheKey); found {
			if entry, ok := cached.(*PolicyEvalCacheEntry); ok {
				// Verify that the resource's version hasn't changed since it was cached.
				// This ensures we're using a fresh evaluation if the resource has been updated.
				if entry.ResourceVersion == resource.GetResourceVersion() {
					logger.V(2).Info("Using cached policy evaluation result",
						"resource", resource.GetName(),
						"kind", resourceGVK.Kind,
						"cacheKey", cacheKey)
					return entry.Result
				}
				logger.V(2).Info("Cached policy evaluation result is stale (resource version mismatch)",
					"resource", resource.GetName(),
					"kind", resourceGVK.Kind,
					"cacheKey", cacheKey,
					"cachedResourceVersion", entry.ResourceVersion,
					"currentResourceVersion", resource.GetResourceVersion())
			}
		}
	}

	// Step 4: Acquire a slot in the evaluation semaphore to limit concurrent policy evaluations.
	// This prevents the controller from being overwhelmed by too many simultaneous evaluations.
	select {
	case r.evaluationSemaphore <- struct{}{}: // Attempt to acquire a token from the semaphore.
		defer func() {
			<-r.evaluationSemaphore // Release the token when the function exits.
		}()
		concurrentEvaluations.Inc() // Increment Prometheus metric for concurrent evaluations.
		defer concurrentEvaluations.Dec()
	case <-ctx.Done(): // If the reconciliation context is cancelled, exit early.
		logger.Info("Context cancelled during semaphore acquisition for policy evaluation", "resource", resource.GetName())
		return []ValidationResult{}
	}

	// Step 5: Create a new context with a timeout for the policy evaluation.
	// This ensures that policy evaluation does not block indefinitely.
	evalCtx, cancel := context.WithTimeout(ctx, EvaluationTimeout)
	defer cancel() // Ensure the context is cancelled when evalCtx is no longer needed.

	// Step 6: Evaluate policies through the policy circuit breaker.
	// This protects against cascading failures if policy evaluation itself becomes unhealthy.
	var violations []ValidationResult
	var evalErr error // Stores the error from the internal evaluation function.

	// Record the start time for latency metrics.
	start := time.Now()
	defer func() {
		// Record the total evaluation latency for all policies.
		evaluationLatency.WithLabelValues("all-policies", resourceGVK.Kind).Observe(time.Since(start).Seconds())
	}()

	// Call the internal policy evaluation function via the circuit breaker.
	err := r.policyCircuitBreaker.Call(func() error {
		violations, evalErr = r.evaluatePoliciesInternal(evalCtx, resource, foundResource, resourceGVK, policies, logger)
		return evalErr // Return the internal evaluation error to the circuit breaker.
	})

	// Step 7: Handle the outcome of the policy evaluation based on the configured FailureMode.
	if err != nil {
		// An error occurred during policy evaluation or the circuit breaker was open.
		if r.FailureMode == FailSecure {
			// In "FailSecure" mode, if evaluation fails, treat it as a blocking violation.
			// This prioritizes security over availability by preventing potentially non-compliant resources.
			logger.Error(err, "Policy evaluation failed, failing secure (blocking resource)",
				"resource", resource.GetName(),
				"failureMode", r.FailureMode)

			// Return a synthetic "evaluation-failure" violation to ensure the resource is blocked.
			return []ValidationResult{{
				PolicyName:   "system",                                         // System-level policy responsible for evaluation.
				RuleName:     "evaluation-failure",                             // Specific rule indicating evaluation failure.
				Violated:     true,                                             // Indicates a violation.
				Action:       "block",                                          // Action is to block the resource.
				Severity:     "critical",                                       // Critical severity for system-level failure.
				ErrorMessage: fmt.Sprintf("Policy evaluation failed: %v", err), // Detailed error message.
				ResourcePath: "system",                                         // Indicates a system-wide issue, not a specific resource path.
			}}
		} else {
			// In "FailSafe" mode, if evaluation fails, log the error but allow the resource.
			// This prioritizes availability by not blocking resources due to controller issues.
			logger.Error(err, "Policy evaluation failed, failing safe (allowing resource)",
				"resource", resource.GetName(),
				"failureMode", r.FailureMode)

			return []ValidationResult{} // No violations to report, resource is allowed.
		}
	}

	// Step 8: Cache the successful evaluation result.
	if r.policyEvalCache != nil {
		cacheEntry := &PolicyEvalCacheEntry{
			ResourceVersion: resource.GetResourceVersion(),
			PolicyVersion:   r.generatePolicyVersion(policies), // A version string for the policies themselves.
			Result:          violations,
			CachedAt:        time.Now(),
		}

		r.policyEvalCache.Set(cacheKey, cacheEntry, PolicyEvalCacheTTL)
		logger.V(2).Info("Cached policy evaluation result", "resource", resource.GetName(), "cacheKey", cacheKey)
	}

	return violations // Return the actual violations found (if any).
}

// evaluatePoliciesInternal performs the core logic of iterating through policies and rules
// and evaluating them against the resource. It is called by evaluatePolicies and
// typically runs within the context of a circuit breaker and timeout.
// It returns a list of ValidationResult and an error if evaluation itself fails.
func (r *ClusterPolicyValidatorReconciler) evaluatePoliciesInternal(
	ctx context.Context,
	resource *unstructured.Unstructured,
	foundResource client.Object,
	resourceGVK schema.GroupVersionKind,
	policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator,
	logger logr.Logger,
) ([]ValidationResult, error) {
	var violations []ValidationResult

	// Iterate through each ClusterPolicyValidator defined.
	for _, policy := range policies {
		// Check context cancellation at the start of each policy evaluation.
		// This allows for early exit if the parent context times out or is cancelled.
		select {
		case <-ctx.Done():
			logger.Info("Context cancelled during internal policy evaluation", "policy", policy.Name, "error", ctx.Err())
			return violations, ctx.Err() // Return collected violations and the context error.
		default:
			// Continue if context is not cancelled.
		}

		// Check if the current policy's match criteria apply to the resource's GVK.
		if !r.policyAppliesToResource(policy, resourceGVK) {
			logger.V(2).Info("Policy does not apply to resource GVK, skipping",
				"policy", policy.Name, "resourceGVK", resourceGVK)
			continue
		}

		// Apply rate limiting for policy evaluation to prevent over-evaluation of a single policy.
		if !r.shouldEvaluatePolicy(policy.Name) {
			logger.V(2).Info("Skipping policy evaluation due to rate limiting", "policy", policy.Name)
			continue
		}

		logger.V(1).Info("Evaluating policy",
			"policy", policy.Name,
			"resource", foundResource.GetName(), // Use GetName() for consistent logging across resource types.
			"kind", resourceGVK.Kind)

		// Increment Prometheus metric for total policy evaluations.
		policyEvaluationTotal.WithLabelValues(policy.Name, resourceGVK.Kind).Inc()

		// Iterate through each validation rule within the current policy.
		for _, rule := range policy.Spec.ValidationRules {
			// Check if the current rule's match criteria apply to the resource's GVK.
			if !r.ruleAppliesToResource(rule, resourceGVK) {
				logger.V(2).Info("Rule does not apply to resource GVK, skipping",
					"policy", policy.Name, "rule", rule.Name, "resourceGVK", resourceGVK)
				continue
			}

			// Evaluate the individual rule against the resource.
			if violation := r.evaluateRule(resource, policy.Name, rule, resourceGVK, logger); violation != nil {
				// If a violation is detected, add it to the list of detected violations.
				violations = append(violations, *violation)
			}
		}
	}

	// Periodically clean up expired entries from the various caches.
	// This helps manage memory and ensure cache freshness.
	r.cleanupCaches()

	// If multiple violations are found, resolve any conflicts based on the configured strategy.
	if len(violations) > 1 {
		violations = r.resolveConflicts(violations, logger)
	}

	// After conflict resolution, check if any of the remaining violations require a "block" action.
	// If a blocking violation is found, we can stop further processing and return it immediately,
	// as this will lead to the resource being blocked.
	for _, violation := range violations {
		if strings.ToLower(violation.Action) == "block" {
			logger.Info("Block action encountered after conflict resolution, stopping evaluation",
				"policy", violation.PolicyName,
				"rule", violation.RuleName,
				"resource", resource.GetName(),
				"kind", resourceGVK.Kind)
			// Return only the blocking violation as it's the decisive one.
			return []ValidationResult{violation}, nil
		}
	}

	return violations, nil // Return the final list of violations (after resolution).
}

// evaluateRule evaluates a single validation rule against an unstructured Kubernetes resource.
// It iterates through the rule's conditions, extracts values from the resource using JQ,
// and validates them against the condition's operator and expected values.
// Returns a pointer to a ValidationResult if a violation is found, otherwise nil.
func (r *ClusterPolicyValidatorReconciler) evaluateRule(
	resource *unstructured.Unstructured,
	policyName string,
	rule clusterpolicyvalidatorv1alpha1.ValidationRule,
	resourceGVK schema.GroupVersionKind,
	logger logr.Logger,
) *ValidationResult {

	// Basic nil checks for robustness.
	if resource == nil {
		logger.Error(nil, "Resource is nil when evaluating rule", "policy", policyName, "rule", rule.Name)
		return nil
	}
	if policyName == "" {
		logger.Error(nil, "Policy name is empty when evaluating rule", "rule", rule.Name)
		return nil
	}

	// Iterate through each condition defined within the rule.
	for _, condition := range rule.Conditions {
		// Validate that the condition key is not empty.
		if condition.Key == "" {
			logger.Error(nil, "Empty condition key found in rule", "rule", rule.Name, "policy", policyName)
			errorTotal.WithLabelValues("empty_condition_key", resourceGVK.Kind).Inc() // Metric for invalid rules.
			continue
		}

		// Extract values from the resource using the condition's key (which is a JQ path).
		values, err := r.extractValues(resource, condition.Key)
		if err != nil {
			logger.Error(err, "Failed to extract values for condition key",
				"key", condition.Key, "kind", resourceGVK.Kind,
				"resource", resource.GetName(), "policy", policyName, "rule", rule.Name)
			errorTotal.WithLabelValues("failed_to_extract_values", resourceGVK.Kind).Inc() // Metric for extraction errors.
			continue
		}

		// Validate the extracted values against the condition's operator and expected values.
		// If the validation fails, a violation is detected.
		if !r.validateCondition(condition, values, logger) {
			logger.Info("Rule violation detected",
				"policy", policyName,
				"rule", rule.Name,
				"condition_key", condition.Key,
				"resource", resource.GetName(),
				"kind", resourceGVK.Kind,
				"severity", rule.Severity,
				"action", rule.Action)

			// Return a new ValidationResult object describing the violation.
			return &ValidationResult{
				PolicyName:   policyName,
				RuleName:     rule.Name,
				Violated:     true,
				Action:       rule.Action,
				Severity:     string(rule.Severity),                             // Convert Severity enum to string.
				ErrorMessage: r.formatErrorMessage(rule.ErrorMessage, resource), // Format a user-friendly error message.
				ResourcePath: condition.Key,                                     // The JQ path that caused the violation.
			}
		}
	}

	return nil // No violations found for this rule.
}

// validateCondition validates a list of actual values against a single policy condition.
// It handles various operators and checks if ANY of the actual values satisfy the condition
// (for "any match" operators) or if ALL of them do (for "all match" operators), implicitly.
// Returns true if the condition is met (no violation), false otherwise.
func (r *ClusterPolicyValidatorReconciler) validateCondition(
	condition clusterpolicyvalidatorv1alpha1.Condition, // The condition to validate against.
	actualValues []interface{}, // The values extracted from the resource.
	logger logr.Logger, // Logger for detailed debugging.
) bool {
	// Handle special cases for empty or non-existent values.
	if len(actualValues) == 0 {
		logger.V(2).Info("No values extracted for condition. Checking for IsEmpty/IsNotEmpty operator.",
			"operator", condition.Operator,
			"expectedValues", condition.Values)
		// If no values are found, "IsEmpty" is true, and other operators are false.
		return condition.Operator == "IsEmpty"
	}

	// Handle "IsEmpty" and "IsNotEmpty" operators first as they don't depend on actual values.
	switch condition.Operator {
	case "IsEmpty":
		// This case is already covered by the len(actualValues) == 0 check above,
		// but kept for explicit clarity.
		return len(actualValues) == 0
	case "IsNotEmpty":
		return len(actualValues) > 0
	}

	// For other operators, iterate through each extracted actual value
	// and check if it satisfies the condition against *any* of the expected values.
	for _, actualVal := range actualValues {
		actualStr := fmt.Sprintf("%v", actualVal) // Convert the actual value to string for comparison.

		if len(condition.Values) > 0 {
			// If expected values are provided, check if any of them match.
			matchFound := false
			for _, expectedVal := range condition.Values {
				if r.evaluateSingleCondition(actualStr, condition.Operator, expectedVal, logger) {
					matchFound = true
					break // Found a match for this actual value, no need to check other expected values.
				}
			}
			// If no match was found for the current actual value, then this specific condition fails.
			// This implies an "AND" logic across multiple actual values for a single condition.
			if !matchFound {
				logger.V(2).Info("No match found for actual value against expected values for condition",
					"actualValue", actualStr, "operator", condition.Operator, "expectedValues", condition.Values)
				return false
			}
		} else {
			// If the operator requires expected values (e.g., Equals, Contains) but none are provided,
			// the condition cannot be met unless it's a special operator like "IsEmpty" or "IsNotEmpty".
			logger.V(2).Info("No expected values provided for condition, returning false", "operator", condition.Operator)
			return false
		}
	}

	// If all actual values (or at least one for "OR" type conditions implicitly handled by for-loop)
	// passed the evaluation against the expected values, the condition is met.
	return true
}

// evaluateSingleCondition performs the actual comparison for a single actual value,
// an operator, and a single expected value.
// It handles string comparisons, regex matching, and numeric comparisons.
func (r *ClusterPolicyValidatorReconciler) evaluateSingleCondition(resourceValue, operator, expectedValue string, logger logr.Logger) bool {
	switch operator {
	case "Equals":
		return resourceValue == expectedValue
	case "NotEquals":
		return resourceValue != expectedValue
	case "Contains":
		return strings.Contains(resourceValue, expectedValue)
	case "NotContains":
		return !strings.Contains(resourceValue, expectedValue)
	case "RegexMatch":
		match, err := regexp.MatchString(expectedValue, resourceValue)
		if err != nil {
			logger.Error(err, "Invalid regex pattern provided for condition", "regex", expectedValue, "value", resourceValue)
			return false // Invalid regex means no match can be determined.
		}
		return match
	case "GreaterThan":
		resourceNum, err1 := strconv.ParseFloat(resourceValue, 64)
		conditionNum, err2 := strconv.ParseFloat(expectedValue, 64)
		// Only perform numeric comparison if both values can be parsed as floats.
		return err1 == nil && err2 == nil && resourceNum > conditionNum
	case "LessThan":
		resourceNum, err1 := strconv.ParseFloat(resourceValue, 64)
		conditionNum, err2 := strconv.ParseFloat(expectedValue, 64)
		// Only perform numeric comparison if both values can be parsed as floats.
		return err1 == nil && err2 == nil && resourceNum < conditionNum
	default:
		// Log an error for unknown operators to help debugging policy definitions.
		logger.Info("Unknown operator encountered during condition evaluation", "operator", operator)
		return false
	}
}

// getCompiledJQ retrieves a compiled JQ query. It first checks a cache for the
// compiled query to avoid redundant parsing and compilation, which can be expensive.
// If not found in cache, it parses and compiles the query and then caches the result.
// Returns the compiled gojq.Code or an error if parsing/compilation fails.
func (r *ClusterPolicyValidatorReconciler) getCompiledJQ(query string) (*gojq.Code, error) {
	// Step 1: Check the JQ cache for the compiled query.
	if r.jqCache != nil {
		if cached, found := r.jqCache.Get(query); found {
			if code, ok := cached.(*gojq.Code); ok {
				jqCacheHits.Inc() // Increment metric for cache hits.
				return code, nil  // Return the cached compiled query.
			}
		}
	}

	jqCacheMisses.Inc() // Increment metric for cache misses.

	// Step 2: If not found in cache, parse the JQ query string.
	q, err := gojq.Parse(query)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jq query '%s': %w", query, err)
	}

	// Step 3: Compile the parsed JQ query.
	code, err := gojq.Compile(q)
	if err != nil {
		return nil, fmt.Errorf("failed to compile jq query '%s': %w", query, err)
	}

	// Step 4: Cache the newly compiled query with its configured TTL.
	if r.jqCache != nil {
		r.jqCache.Set(query, code, JQCacheTTL)
	}

	return code, nil
}

// extractValues retrieves values from an unstructured Kubernetes resource given a JQ-compatible key path.
// It transforms the key path (e.g., "spec.containers[*].image") into a JQ expression
// and then uses evaluateJQ to run it against the resource.
// Returns a slice of interfaces representing the extracted values, or an error.
func (r *ClusterPolicyValidatorReconciler) extractValues(resource *unstructured.Unstructured, keyPath string) ([]interface{}, error) {
	// Convert the Kubernetes-style path (e.g., "spec.containers[*].image")
	// into a valid JQ expression (e.g., ".spec.containers[].image").
	// The `try (...) catch empty` ensures that if a path does not exist, it results in an empty array
	// instead of an error, allowing for optional fields.
	jqExpr := "." + strings.ReplaceAll(keyPath, "[*]", "[]")
	jqExpr = fmt.Sprintf("try (%s) catch empty", jqExpr)

	// Evaluate the constructed JQ expression against the resource.
	return r.evaluateJQ(resource, jqExpr)
}

// evaluateJQ runs a given JQ expression against an unstructured Kubernetes resource.
// It leverages the cached compiled JQ queries for performance.
// Returns a slice of interfaces containing the results of the JQ query, or an error.
func (r *ClusterPolicyValidatorReconciler) evaluateJQ(resource *unstructured.Unstructured, query string) ([]interface{}, error) {
	// Get the compiled JQ code for the query, using the cache.
	code, err := r.getCompiledJQ(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get compiled JQ query for '%s': %w", query, err)
	}

	// Run the compiled JQ query against the resource's underlying map (which is a map[string]interface{}).
	iter := code.Run(resource.Object)
	var results []interface{}

	// Iterate over the results of the JQ query.
	for {
		v, ok := iter.Next() // Get the next value.
		if !ok {
			break // No more values, break the loop.
		}
		if err, isErr := v.(error); isErr {
			// If the value is an error, return it.
			return nil, fmt.Errorf("error running jq query '%s': %w", query, err)
		}
		results = append(results, v) // Add the successful result to the list.
	}

	return results, nil
}

// policyAppliesToResource checks if at least one rule within a ClusterPolicyValidator
// explicitly matches the GroupVersionKind (GVK) of the target resource.
// If any rule applies, the policy itself is considered applicable.
func (r *ClusterPolicyValidatorReconciler) policyAppliesToResource(
	policy clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator,
	resourceGVK schema.GroupVersionKind,
) bool {
	// Iterate through all validation rules defined in the policy.
	for _, rule := range policy.Spec.ValidationRules {
		// If any rule is found to apply to the resource, then the policy applies.
		if r.ruleAppliesToResource(rule, resourceGVK) {
			return true
		}
	}
	return false // No rule in this policy applies to the given resource GVK.
}

// ruleAppliesToResource checks if a specific ValidationRule's `MatchResources.Kinds`
// explicitly includes the GroupVersionKind (GVK) of the target resource.
// If `MatchResources.Kinds` is empty, the rule applies to all resource kinds.
func (r *ClusterPolicyValidatorReconciler) ruleAppliesToResource(
	rule clusterpolicyvalidatorv1alpha1.ValidationRule,
	resourceGVK schema.GroupVersionKind,
) bool {
	// If no specific kinds are listed in the rule, it means the rule applies to ALL resource kinds.
	if len(rule.MatchResources.Kinds) == 0 {
		return true
	}

	// Check if the resource's Kind matches any of the kinds specified in the rule's `MatchResources.Kinds`.
	for _, kind := range rule.MatchResources.Kinds {
		// Use strings.EqualFold for case-insensitive comparison.
		if strings.EqualFold(kind, resourceGVK.Kind) {
			return true // Found a match, the rule applies.
		}
	}

	return false // The resource's Kind does not match any of the specified kinds in the rule.
}

// shouldEvaluatePolicy implements a simple rate limiting mechanism for policy evaluations.
// It ensures that a given policy (identified by its name) is not evaluated more frequently
// than a defined interval (currently 1 second). This helps prevent a single policy from
// consuming excessive resources due to rapid events.
func (r *ClusterPolicyValidatorReconciler) shouldEvaluatePolicy(policyName string) bool {
	r.evalLimiterMu.Lock() // Acquire a write lock to protect the policyEvalLimiter map.
	defer r.evalLimiterMu.Unlock()

	// Check if a timer already exists for this policy.
	if timer, exists := r.policyEvalLimiter[policyName]; exists {
		// If a timer exists, check if it has expired.
		select {
		case <-timer.C:
			// If the timer channel is ready, it means the delay has passed.
			// Delete the old timer and allow evaluation.
			delete(r.policyEvalLimiter, policyName)
			return true
		default:
			// If the timer has not expired yet, it means the policy is still rate-limited.
			return false // Do not evaluate this policy yet.
		}
	}

	// If no timer exists for this policy, it means it's ready for evaluation.
	// Create a new timer to enforce the minimum delay for the next evaluation.
	r.policyEvalLimiter[policyName] = time.NewTimer(time.Second) // Set a 1-second delay.
	return true
}

// resolveConflicts processes a list of validation violations and applies the configured
// conflict resolution strategy to determine the final set of applicable violations.
// This is crucial when multiple policies or rules might generate conflicting actions
// or severities for the same resource or resource path.
func (r *ClusterPolicyValidatorReconciler) resolveConflicts(violations []ValidationResult, logger logr.Logger) []ValidationResult {
	// If there's 1 or fewer violations, no conflict resolution is needed.
	if len(violations) <= 1 {
		return violations
	}

	// Group violations by their `ResourcePath`. This helps in resolving conflicts
	// for specific parts of the resource (e.g., two rules blocking different aspects of the same container).
	conflictGroups := make(map[string][]ValidationResult)
	for _, violation := range violations {
		key := violation.ResourcePath // The path within the resource where the violation occurred.
		conflictGroups[key] = append(conflictGroups[key], violation)
	}

	var resolvedViolations []ValidationResult

	// Iterate through each group of violations.
	for path, group := range conflictGroups {
		// If a group has only one violation, there's no conflict for that specific path.
		if len(group) == 1 {
			resolvedViolations = append(resolvedViolations, group[0])
			continue
		}

		// We have multiple violations for the same `ResourcePath`, meaning a conflict needs resolution.
		logger.Info("Resolving policy conflicts for resource path",
			"resource_path", path,
			"conflict_count", len(group),
			"strategy", r.ConflictResolution)

		// Increment Prometheus metric for policy conflicts based on the resolution strategy.
		policyConflicts.WithLabelValues(string(r.ConflictResolution), path).Inc()

		// Apply the specific conflict resolution strategy configured for the reconciler.
		resolved := r.applyConflictResolution(group, logger)
		resolvedViolations = append(resolvedViolations, resolved...) // Add the resolved violations to the final list.
	}

	return resolvedViolations
}

// applyConflictResolution dispatches to the specific conflict resolution function
// based on the `ConflictResolution` strategy configured for the reconciler.
// It takes a group of conflicting violations and returns the subset of violations
// that are deemed definitive according to the chosen strategy.
func (r *ClusterPolicyValidatorReconciler) applyConflictResolution(violations []ValidationResult, logger logr.Logger) []ValidationResult {
	switch r.ConflictResolution {
	case ConflictResolutionMostRestrictive:
		// Selects the violation(s) with the most restrictive action (e.g., "block" over "warn").
		return r.selectMostRestrictive(violations, logger)
	case ConflictResolutionHighestSeverity:
		// Selects the violation(s) with the highest severity (e.g., "critical" over "low").
		return r.selectHighestSeverity(violations, logger)
	case ConflictResolutionFirstMatch:
		fallthrough // Fallthrough to default behavior for "FirstMatch".
	default:
		// If the strategy is "FirstMatch" or any unknown/unspecified strategy,
		// it defaults to returning only the first violation in the group.
		// This approach implies an arbitrary ordering which might not be deterministic
		// unless the input `violations` slice is consistently sorted.
		logger.V(1).Info("Using default (first match) conflict resolution strategy",
			"strategy", r.ConflictResolution,
			"violations_count", len(violations))
		return violations[:1]
	}
}

// selectMostRestrictive determines the most restrictive action among a set of conflicting violations.
// It prioritizes actions in the order: "block" > "warn" > "audit" > "continue".
// If multiple violations have the same highest priority action, all of them are returned.
func (r *ClusterPolicyValidatorReconciler) selectMostRestrictive(violations []ValidationResult, logger logr.Logger) []ValidationResult {
	// Define the priority of different actions, higher number means more restrictive.
	actionPriority := map[string]int{
		"block":    4,
		"warn":     3,
		"audit":    2,
		"continue": 1,
	}

	maxPriority := 0
	var mostRestrictive []ValidationResult

	// Iterate through violations to find the highest priority action.
	for _, violation := range violations {
		// Convert action to lowercase for case-insensitive comparison.
		priority := actionPriority[strings.ToLower(violation.Action)]
		if priority > maxPriority {
			// New highest priority found, reset the list.
			maxPriority = priority
			mostRestrictive = []ValidationResult{violation}
		} else if priority == maxPriority {
			// Another violation with the same highest priority, add it to the list.
			mostRestrictive = append(mostRestrictive, violation)
		}
	}

	// Log the outcome of the conflict resolution.
	if len(mostRestrictive) > 0 {
		logger.Info("Selected most restrictive action for conflict resolution",
			"action", mostRestrictive[0].Action, // Log the action of the first selected violation.
			"selected_count", len(mostRestrictive))
	} else {
		// This case should ideally not happen if violations slice is not empty.
		logger.Info("No most restrictive action found for violations", "violations_count", len(violations))
	}

	return mostRestrictive
}

// selectHighestSeverity determines the violation(s) with the highest severity among a set of conflicting violations.
// It prioritizes severities in the order: "critical" > "high" > "medium" > "low".
// If multiple violations have the same highest severity, all of them are returned.
func (r *ClusterPolicyValidatorReconciler) selectHighestSeverity(violations []ValidationResult, logger logr.Logger) []ValidationResult {
	// Define the priority of different severities, higher number means higher severity.
	severityPriority := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
	}

	maxPriority := 0
	var highestSeverity []ValidationResult

	// Iterate through violations to find the highest priority severity.
	for _, violation := range violations {
		// Convert severity to lowercase for case-insensitive comparison.
		priority := severityPriority[strings.ToLower(violation.Severity)]
		if priority > maxPriority {
			// New highest priority found, reset the list.
			maxPriority = priority
			highestSeverity = []ValidationResult{violation}
		} else if priority == maxPriority {
			// Another violation with the same highest priority, add it to the list.
			highestSeverity = append(highestSeverity, violation)
		}
	}

	// Log the outcome of the conflict resolution.
	if len(highestSeverity) > 0 {
		logger.Info("Selected highest severity for conflict resolution",
			"severity", highestSeverity[0].Severity, // Log the severity of the first selected violation.
			"selected_count", len(highestSeverity))
	} else {
		// This case should ideally not happen if violations slice is not empty.
		logger.Info("No highest severity violation found", "violations_count", len(violations))
	}

	return highestSeverity
}
