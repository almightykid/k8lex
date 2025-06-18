// Package clusterpolicyvalidator implements a Kubernetes controller for validating resources against policies.
// It provides comprehensive error handling, metrics collection, and policy enforcement capabilities.

package clusterpolicyvalidator

import (
	"fmt"
	"strings"
)

// Error categories for better error handling and reporting
const (
	// ErrorCategoryPolicy represents errors related to policy evaluation and enforcement
	ErrorCategoryPolicy = "policy"
	// ErrorCategoryResource represents errors related to resource processing and validation
	ErrorCategoryResource = "resource"
	// ErrorCategoryValidation represents errors related to validation logic
	ErrorCategoryValidation = "validation"
	// ErrorCategoryConfiguration represents errors related to configuration and setup
	ErrorCategoryConfiguration = "configuration"
)

// PolicyError represents errors that occur during policy evaluation
type PolicyError struct {
	Category     string // Error category (e.g., "policy", "resource")
	PolicyName   string // Name of the policy that caused the error
	RuleName     string // Name of the rule that caused the error
	ResourcePath string // Path to the resource field that caused the error
	Message      string // Human-readable error message
	Err          error  // Original error if any
}

func (e *PolicyError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] policy '%s' rule '%s' at path '%s': %s (caused by: %v)",
			e.Category, e.PolicyName, e.RuleName, e.ResourcePath, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] policy '%s' rule '%s' at path '%s': %s",
		e.Category, e.PolicyName, e.RuleName, e.ResourcePath, e.Message)
}

func (e *PolicyError) Unwrap() error {
	return e.Err
}

// ResourceError represents errors that occur during resource processing
type ResourceError struct {
	Category     string // Error category (e.g., "resource", "validation")
	ResourceName string // Name of the resource that caused the error
	ResourceKind string // Kind of the resource that caused the error
	Namespace    string // Namespace of the resource
	Message      string // Human-readable error message
	Err          error  // Original error if any
}

func (e *ResourceError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] resource '%s' of kind '%s' in namespace '%s': %s (caused by: %v)",
			e.Category, e.ResourceName, e.ResourceKind, e.Namespace, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] resource '%s' of kind '%s' in namespace '%s': %s",
		e.Category, e.ResourceName, e.ResourceKind, e.Namespace, e.Message)
}

func (e *ResourceError) Unwrap() error {
	return e.Err
}

// ValidationError represents errors that occur during validation
type ValidationError struct {
	Category     string // Error category (e.g., "validation", "policy")
	ResourceName string // Name of the resource being validated
	ResourceKind string // Kind of the resource being validated
	Field        string // Field that failed validation
	Message      string // Human-readable error message
	Err          error  // Original error if any
}

func (e *ValidationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] validation failed for resource '%s' of kind '%s' at field '%s': %s (caused by: %v)",
			e.Category, e.ResourceName, e.ResourceKind, e.Field, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] validation failed for resource '%s' of kind '%s' at field '%s': %s",
		e.Category, e.ResourceName, e.ResourceKind, e.Field, e.Message)
}

func (e *ValidationError) Unwrap() error {
	return e.Err
}

// ConfigurationError represents errors that occur during configuration
type ConfigurationError struct {
	Category  string // Error category (e.g., "configuration", "setup")
	Component string // Component that caused the error
	Message   string // Human-readable error message
	Err       error  // Original error if any
}

func (e *ConfigurationError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%s] configuration error in component '%s': %s (caused by: %v)",
			e.Category, e.Component, e.Message, e.Err)
	}
	return fmt.Sprintf("[%s] configuration error in component '%s': %s",
		e.Category, e.Component, e.Message)
}

func (e *ConfigurationError) Unwrap() error {
	return e.Err
}

// Helper functions to create error instances

// NewPolicyError creates a new PolicyError with the given parameters
func NewPolicyError(category, policyName, ruleName, resourcePath, message string, err error) error {
	return &PolicyError{
		Category:     category,
		PolicyName:   policyName,
		RuleName:     ruleName,
		ResourcePath: resourcePath,
		Message:      message,
		Err:          err,
	}
}

// NewResourceError creates a new ResourceError with the given parameters
func NewResourceError(category, resourceName, resourceKind, namespace, message string, err error) error {
	return &ResourceError{
		Category:     category,
		ResourceName: resourceName,
		ResourceKind: resourceKind,
		Namespace:    namespace,
		Message:      message,
		Err:          err,
	}
}

// NewValidationError creates a new ValidationError with the given parameters
func NewValidationError(category, resourceName, resourceKind, field, message string, err error) error {
	return &ValidationError{
		Category:     category,
		ResourceName: resourceName,
		ResourceKind: resourceKind,
		Field:        field,
		Message:      message,
		Err:          err,
	}
}

// NewConfigurationError creates a new ConfigurationError with the given parameters
func NewConfigurationError(category, component, message string, err error) error {
	return &ConfigurationError{
		Category:  category,
		Component: component,
		Message:   message,
		Err:       err,
	}
}

// IsRetryableError determines if an error should trigger a retry
func IsRetryableError(err error) bool {
	// Check for known non-retryable error patterns
	if err == nil {
		return false
	}

	// Check error type and content for retryability
	switch e := err.(type) {
	case *PolicyError:
		return isRetryablePolicyError(e)
	case *ResourceError:
		return isRetryableResourceError(e)
	case *ValidationError:
		return false // Validation errors are typically not retryable
	case *ConfigurationError:
		return false // Configuration errors are typically not retryable
	default:
		// For unknown error types, check error message for retryable patterns
		errMsg := strings.ToLower(err.Error())
		return strings.Contains(errMsg, "timeout") ||
			strings.Contains(errMsg, "connection refused") ||
			strings.Contains(errMsg, "connection reset") ||
			strings.Contains(errMsg, "temporary") ||
			strings.Contains(errMsg, "retry")
	}
}

// isRetryablePolicyError determines if a PolicyError should trigger a retry
func isRetryablePolicyError(err *PolicyError) bool {
	// Policy evaluation errors are typically not retryable
	// unless they are caused by temporary issues
	if err.Err != nil {
		return IsRetryableError(err.Err)
	}
	return false
}

// isRetryableResourceError determines if a ResourceError should trigger a retry
func isRetryableResourceError(err *ResourceError) bool {
	// Resource processing errors are retryable if they are caused by
	// temporary issues like network problems or timeouts
	if err.Err != nil {
		return IsRetryableError(err.Err)
	}
	return false
}
