package clusterpolicyvalidator

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the ClusterPolicyValidator
type Config struct {
	// Performance settings
	MaxConcurrentReconciles  int
	MaxConcurrentEvaluations int
	EvaluationTimeout        time.Duration

	// Cache settings
	JQCacheMaxSize       int
	PolicyCacheSize      int
	PolicyEvalCacheSize  int
	CacheCleanupInterval time.Duration

	// Circuit breaker settings
	CircuitBreakerThreshold int
	CircuitBreakerTimeout   time.Duration

	// Retry settings
	MaxRetries        int
	BaseBackoffDelay  time.Duration
	MaxBackoffDelay   time.Duration
	BackoffMultiplier float64
	JitterMaxFactor   float64

	// Failure mode
	FailureMode FailureMode

	// Conflict resolution
	ConflictResolution PolicyConflictResolution
}

// DefaultConfig returns a Config with default values
func DefaultConfig() *Config {
	return &Config{
		MaxConcurrentReconciles:  5,
		MaxConcurrentEvaluations: 10,
		EvaluationTimeout:        30 * time.Second,

		JQCacheMaxSize:       1000,
		PolicyCacheSize:      100,
		PolicyEvalCacheSize:  1000,
		CacheCleanupInterval: 1 * time.Minute,

		CircuitBreakerThreshold: 5,
		CircuitBreakerTimeout:   60 * time.Second,

		MaxRetries:        5,
		BaseBackoffDelay:  1 * time.Second,
		MaxBackoffDelay:   300 * time.Second,
		BackoffMultiplier: 2.0,
		JitterMaxFactor:   0.1,

		FailureMode:        FailSecure,
		ConflictResolution: ConflictResolutionMostRestrictive,
	}
}

// LoadConfig loads configuration from environment variables with defaults
func LoadConfig() (*Config, error) {
	config := DefaultConfig()

	// Helper function to get int from env with default
	getInt := func(key string, def int) int {
		if val := os.Getenv(key); val != "" {
			if i, err := strconv.Atoi(val); err == nil {
				return i
			}
		}
		return def
	}

	// Helper function to get duration from env with default
	getDuration := func(key string, def time.Duration) time.Duration {
		if val := os.Getenv(key); val != "" {
			if d, err := time.ParseDuration(val); err == nil {
				return d
			}
		}
		return def
	}

	// Helper function to get float from env with default
	getFloat := func(key string, def float64) float64 {
		if val := os.Getenv(key); val != "" {
			if f, err := strconv.ParseFloat(val, 64); err == nil {
				return f
			}
		}
		return def
	}

	// Load configuration from environment variables
	config.MaxConcurrentReconciles = getInt("K8LEX_MAX_CONCURRENT_RECONCILES", config.MaxConcurrentReconciles)
	config.MaxConcurrentEvaluations = getInt("K8LEX_MAX_CONCURRENT_EVALUATIONS", config.MaxConcurrentEvaluations)
	config.EvaluationTimeout = getDuration("K8LEX_EVALUATION_TIMEOUT", config.EvaluationTimeout)

	config.JQCacheMaxSize = getInt("K8LEX_JQ_CACHE_MAX_SIZE", config.JQCacheMaxSize)
	config.PolicyCacheSize = getInt("K8LEX_POLICY_CACHE_SIZE", config.PolicyCacheSize)
	config.PolicyEvalCacheSize = getInt("K8LEX_POLICY_EVAL_CACHE_SIZE", config.PolicyEvalCacheSize)
	config.CacheCleanupInterval = getDuration("K8LEX_CACHE_CLEANUP_INTERVAL", config.CacheCleanupInterval)

	config.CircuitBreakerThreshold = getInt("K8LEX_CIRCUIT_BREAKER_THRESHOLD", config.CircuitBreakerThreshold)
	config.CircuitBreakerTimeout = getDuration("K8LEX_CIRCUIT_BREAKER_TIMEOUT", config.CircuitBreakerTimeout)

	config.MaxRetries = getInt("K8LEX_MAX_RETRIES", config.MaxRetries)
	config.BaseBackoffDelay = getDuration("K8LEX_BASE_BACKOFF_DELAY", config.BaseBackoffDelay)
	config.MaxBackoffDelay = getDuration("K8LEX_MAX_BACKOFF_DELAY", config.MaxBackoffDelay)
	config.BackoffMultiplier = getFloat("K8LEX_BACKOFF_MULTIPLIER", config.BackoffMultiplier)
	config.JitterMaxFactor = getFloat("K8LEX_JITTER_MAX_FACTOR", config.JitterMaxFactor)

	// Load failure mode
	if val := os.Getenv("K8LEX_FAILURE_MODE"); val != "" {
		switch FailureMode(val) {
		case FailSecure, FailSafe:
			config.FailureMode = FailureMode(val)
		default:
			return nil, fmt.Errorf("invalid failure mode: %s", val)
		}
	}

	// Load conflict resolution
	if val := os.Getenv("K8LEX_CONFLICT_RESOLUTION"); val != "" {
		switch PolicyConflictResolution(val) {
		case ConflictResolutionMostRestrictive,
			ConflictResolutionFirstMatch,
			ConflictResolutionHighestSeverity:
			config.ConflictResolution = PolicyConflictResolution(val)
		default:
			return nil, fmt.Errorf("invalid conflict resolution: %s", val)
		}
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.MaxConcurrentReconciles < 1 {
		return fmt.Errorf("max concurrent reconciles must be at least 1")
	}
	if c.MaxConcurrentEvaluations < 1 {
		return fmt.Errorf("max concurrent evaluations must be at least 1")
	}
	if c.EvaluationTimeout < time.Second {
		return fmt.Errorf("evaluation timeout must be at least 1 second")
	}

	if c.JQCacheMaxSize < 1 {
		return fmt.Errorf("JQ cache max size must be at least 1")
	}
	if c.PolicyCacheSize < 1 {
		return fmt.Errorf("policy cache size must be at least 1")
	}
	if c.PolicyEvalCacheSize < 1 {
		return fmt.Errorf("policy evaluation cache size must be at least 1")
	}
	if c.CacheCleanupInterval < time.Second {
		return fmt.Errorf("cache cleanup interval must be at least 1 second")
	}

	if c.CircuitBreakerThreshold < 1 {
		return fmt.Errorf("circuit breaker threshold must be at least 1")
	}
	if c.CircuitBreakerTimeout < time.Second {
		return fmt.Errorf("circuit breaker timeout must be at least 1 second")
	}

	if c.MaxRetries < 0 {
		return fmt.Errorf("max retries cannot be negative")
	}
	if c.BaseBackoffDelay < time.Millisecond {
		return fmt.Errorf("base backoff delay must be at least 1 millisecond")
	}
	if c.MaxBackoffDelay < c.BaseBackoffDelay {
		return fmt.Errorf("max backoff delay must be greater than base backoff delay")
	}
	if c.BackoffMultiplier <= 1.0 {
		return fmt.Errorf("backoff multiplier must be greater than 1.0")
	}
	if c.JitterMaxFactor < 0 || c.JitterMaxFactor > 1 {
		return fmt.Errorf("jitter max factor must be between 0 and 1")
	}

	return nil
}

// String returns a string representation of the configuration
func (c *Config) String() string {
	return fmt.Sprintf(`
Configuration:
  Performance:
    Max Concurrent Reconciles: %d
    Max Concurrent Evaluations: %d
    Evaluation Timeout: %s

  Cache:
    JQ Cache Max Size: %d
    Policy Cache Size: %d
    Policy Eval Cache Size: %d
    Cache Cleanup Interval: %s

  Circuit Breaker:
    Threshold: %d
    Timeout: %s

  Retry:
    Max Retries: %d
    Base Backoff Delay: %s
    Max Backoff Delay: %s
    Backoff Multiplier: %.2f
    Jitter Max Factor: %.2f

  Failure Mode: %s
  Conflict Resolution: %s
`,
		c.MaxConcurrentReconciles,
		c.MaxConcurrentEvaluations,
		c.EvaluationTimeout,
		c.JQCacheMaxSize,
		c.PolicyCacheSize,
		c.PolicyEvalCacheSize,
		c.CacheCleanupInterval,
		c.CircuitBreakerThreshold,
		c.CircuitBreakerTimeout,
		c.MaxRetries,
		c.BaseBackoffDelay,
		c.MaxBackoffDelay,
		c.BackoffMultiplier,
		c.JitterMaxFactor,
		c.FailureMode,
		c.ConflictResolution,
	)
}
