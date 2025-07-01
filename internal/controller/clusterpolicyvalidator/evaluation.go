package clusterpolicyvalidator

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	clusterpolicyvalidatorv1alpha1 "github.com/almightykid/k8lex/api/clusterpolicyvalidator/v1alpha1"
	"github.com/go-logr/logr"
	"github.com/itchyny/gojq"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// evaluatePolicies orchestrates the policy evaluation process for a given Kubernetes resource.

// to ensure efficient and resilient policy enforcement.
// It returns a list of ValidationResult indicating any policy violations found.
func (r *ClusterPolicyValidatorReconciler) evaluatePolicies(
	ctx context.Context,
	resource *unstructured.Unstructured,
	foundResource client.Object,
	resourceGVK schema.GroupVersionKind,
	policies []clusterpolicyvalidatorv1alpha1.ClusterPolicyValidator,
	logger logr.Logger,
) []ValidationResult {
	var violations []ValidationResult

	// Si el recurso tiene anotación de bypass, no evaluamos políticas.
	if r.shouldBypassPolicies(foundResource) {
		return violations
	}

	// Itera sobre todas las policies y reglas.
	for _, policy := range policies {
		if !r.policyAppliesToResource(policy, resourceGVK) {
			continue
		}
		for _, rule := range policy.Spec.ValidationRules {
			if !r.ruleAppliesToResource(rule, resourceGVK) {
				continue
			}
			if violation := r.evaluateRule(resource, policy.Name, rule, resourceGVK, logger); violation != nil {
				violations = append(violations, *violation)
			}
		}
	}

	return violations
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
			continue
		}

		// Extract values from the resource using the condition's key (which is a JQ path).
		values, err := r.extractValues(resource, condition.Key)
		if err != nil {
			logger.Error(err, "Failed to extract values for condition key",
				"key", condition.Key, "kind", resourceGVK.Kind,
				"resource", resource.GetName(), "policy", policyName, "rule", rule.Name)

			continue
		}

		// Validate the extracted values against the condition's operator and expected values.
		// If the validation fails, a violation is detected.
		if r.validateCondition(condition, values, logger) {
			logger.Info("Rule violation detected",
				"policy", policyName,
				"rule", rule.Name,
				"condition_key", condition.Key,
				"resource", resource.GetName(),
				"kind", resourceGVK.Kind,
				"action", rule.Action)

			// Return a new ValidationResult object describing the violation.
			return &ValidationResult{
				PolicyName:   policyName,
				RuleName:     rule.Name,
				Violated:     true,
				Action:       rule.Action,   // Convert Severity enum to string.
				ResourcePath: condition.Key, // The JQ path that caused the violation.
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
	// Parse the JQ query string.
	q, err := gojq.Parse(query)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jq query '%s': %w", query, err)
	}

	// Compile the parsed JQ query.
	code, err := gojq.Compile(q)
	if err != nil {
		return nil, fmt.Errorf("failed to compile jq query '%s': %w", query, err)
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
		"block":    3,
		"warn":     2,
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
