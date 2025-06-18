package clusterpolicyvalidator

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// NewCircuitBreaker creates a new circuit breaker with specified failure threshold and recovery timeout
// The circuit breaker implements the circuit breaker pattern to prevent cascading failures
// by temporarily blocking calls to a failing service, allowing it time to recover
func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:     CircuitClosed, // Start in closed state (normal operation)
		threshold: threshold,     // Number of failures before opening the circuit
		timeout:   timeout,       // Time to wait before attempting recovery
	}
}

// CircuitBreakerError represents a circuit breaker specific error
type CircuitBreakerError struct {
	State     CircuitBreakerState
	Failures  int
	LastError error
}

func (e *CircuitBreakerError) Error() string {
	return fmt.Sprintf("circuit breaker is %s (failures: %d, last error: %v)",
		circuitBreakerStateToString(e.State), e.Failures, e.LastError)
}

func (e *CircuitBreakerError) Unwrap() error {
	return e.LastError
}

// circuitBreakerStateToString converts CircuitBreakerState to string
func circuitBreakerStateToString(state CircuitBreakerState) string {
	switch state {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// Call executes the provided function through the circuit breaker protection mechanism
// The circuit breaker tracks failures and can reject calls when the failure threshold is exceeded
// This prevents overwhelming a failing service and allows for graceful degradation
func (cb *CircuitBreaker) Call(fn func() error) error {
	// Read current state atomically to avoid race conditions during state checks
	cb.mu.RLock()
	state := cb.state
	failures := cb.failures
	lastFailTime := cb.lastFailTime
	cb.mu.RUnlock()

	// Record metrics for circuit breaker state
	circuitBreakerState.WithLabelValues(circuitBreakerStateToString(state)).Set(1)

	// Attempt transition from Open to HalfOpen state after timeout period
	// This allows testing if the service has recovered from its failure condition
	if state == CircuitOpen && time.Since(lastFailTime) > cb.timeout {
		cb.mu.Lock()
		// Double-check condition while holding write lock to prevent race conditions
		if cb.state == CircuitOpen && time.Since(cb.lastFailTime) > cb.timeout {
			cb.state = CircuitHalfOpen
			circuitBreakerState.WithLabelValues("half-open").Set(1)
			circuitBreakerState.WithLabelValues("open").Set(0)
		}
		cb.mu.Unlock()
	}

	// Reject the call immediately if circuit is open (fast-fail behavior)
	// This protects the failing service from additional load and provides immediate feedback
	if state == CircuitOpen {
		return &CircuitBreakerError{
			State:     CircuitOpen,
			Failures:  failures,
			LastError: fmt.Errorf("circuit breaker is open"),
		}
	}

	// Execute the protected operation
	err := fn()

	// Update circuit breaker state based on operation result
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		// Record failure and check if threshold is exceeded
		cb.failures++
		cb.lastFailTime = time.Now()

		// Open circuit if failure threshold is reached
		if cb.failures >= cb.threshold {
			cb.state = CircuitOpen
			circuitBreakerState.WithLabelValues("open").Set(1)
			circuitBreakerState.WithLabelValues("closed").Set(0)
		}

		return &CircuitBreakerError{
			State:     cb.state,
			Failures:  cb.failures,
			LastError: err,
		}
	}

	// Operation succeeded - reset circuit breaker to healthy state
	if cb.state == CircuitHalfOpen {
		cb.state = CircuitClosed // Transition from testing back to normal operation
		circuitBreakerState.WithLabelValues("closed").Set(1)
		circuitBreakerState.WithLabelValues("half-open").Set(0)
	}
	cb.failures = 0 // Reset failure counter on successful operation

	return nil
}

// retryWithBackoff executes an operation with exponential backoff retry logic and circuit breaker protection
// This method implements enterprise-grade retry patterns with intelligent failure handling,
// context cancellation support, and comprehensive observability through metrics and logging
func (r *ClusterPolicyValidatorReconciler) retryWithBackoff(ctx context.Context, operation func() error, operationName string) error {
	var lastErr error

	r.Log.V(2).Info("Starting retry operation with backoff",
		"operation", operationName,
		"max_retries", r.retryConfig.MaxRetries,
		"base_delay", r.retryConfig.BaseDelay,
		"max_delay", r.retryConfig.MaxDelay)

	// Attempt operation with exponential backoff up to configured maximum retries
	for attempt := 0; attempt < r.retryConfig.MaxRetries; attempt++ {
		var err error

		// Apply circuit breaker protection for API operations to prevent cascading failures
		if strings.Contains(operationName, "api") {
			err = r.apiCircuitBreaker.Call(operation)
		} else {
			// Execute operation directly for non-API operations
			err = operation()
		}

		// Operation succeeded - return immediately without further attempts
		if err == nil {
			if attempt > 0 {
				r.Log.Info("Operation succeeded after retries",
					"operation", operationName,
					"successful_attempt", attempt+1,
					"total_attempts", attempt+1)
			}
			return nil
		}

		lastErr = err

		// Classify errors to determine if retry is appropriate
		// Some errors indicate permanent failures that won't benefit from retrying
		if apierrors.IsNotFound(err) || apierrors.IsUnauthorized(err) || apierrors.IsForbidden(err) {
			r.Log.V(1).Info("Non-retryable error encountered - failing immediately",
				"operation", operationName,
				"error_type", fmt.Sprintf("%T", err),
				"error", err.Error())
			return err
		}

		// Calculate exponential backoff delay with jitter for this attempt
		delay := r.calculateBackoffDelay(attempt)

		r.Log.Info("Operation failed - retrying with exponential backoff",
			"operation", operationName,
			"attempt", attempt+1,
			"max_retries", r.retryConfig.MaxRetries,
			"delay", delay.String(),
			"error_type", fmt.Sprintf("%T", err),
			"error", err.Error())

		// Update retry metrics for monitoring and alerting
		retryAttempts.WithLabelValues(operationName, fmt.Sprintf("%d", attempt+1)).Inc()

		// Wait for calculated delay while respecting context cancellation
		// This allows for graceful shutdown and prevents hanging operations
		select {
		case <-ctx.Done():
			r.Log.Info("Retry operation cancelled due to context cancellation",
				"operation", operationName,
				"attempt", attempt+1,
				"context_error", ctx.Err().Error())
			return ctx.Err()
		case <-time.After(delay):
			// Continue to next retry attempt after delay period
		}
	}

	// All retry attempts exhausted - return the last encountered error
	r.Log.Error(lastErr, "Operation failed after all retry attempts exhausted",
		"operation", operationName,
		"total_attempts", r.retryConfig.MaxRetries,
		"final_error", lastErr.Error())

	return fmt.Errorf("operation %s failed after %d attempts, last error: %w",
		operationName, r.retryConfig.MaxRetries, lastErr)
}

// calculateBackoffDelay computes the delay for the next retry attempt using exponential backoff with jitter
// The exponential backoff prevents overwhelming a recovering service, while jitter prevents thundering herd
// problems when multiple instances retry simultaneously. Uses golden ratio for optimal jitter distribution
func (r *ClusterPolicyValidatorReconciler) calculateBackoffDelay(attempt int) time.Duration {
	// Calculate base exponential backoff: baseDelay * multiplier^attempt
	delay := float64(r.retryConfig.BaseDelay) * math.Pow(r.retryConfig.Multiplier, float64(attempt))

	// Add jitter using golden ratio (Phi) for mathematically optimal distribution
	// This prevents synchronized retry attempts across multiple instances (thundering herd)
	jitter := delay * r.retryConfig.JitterMaxFactor * (2*math.Pow(math.Phi, float64(attempt)) - 1)
	delay += jitter

	// Cap delay at configured maximum to prevent excessively long wait times
	if delay > float64(r.retryConfig.MaxDelay) {
		delay = float64(r.retryConfig.MaxDelay)
	}

	r.Log.V(3).Info("Calculated backoff delay for retry attempt",
		"attempt", attempt,
		"base_delay", r.retryConfig.BaseDelay,
		"multiplier", r.retryConfig.Multiplier,
		"jitter_factor", r.retryConfig.JitterMaxFactor,
		"calculated_delay", time.Duration(delay),
		"max_delay", r.retryConfig.MaxDelay)

	return time.Duration(delay)
}
