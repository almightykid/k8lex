package clusterpolicyvalidator

import (
	"context"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// Constants for annotations
	PolicyBlockedAnnotation      = "k8lex.io/policy-blocked"
	OriginalReplicasAnnotation   = "k8lex.io/original-replicas"
	BlockedReasonAnnotation      = "k8lex.io/blocked-reason"
	PolicyViolationAnnotation    = "k8lex.io/policy-violation"
	ViolationDetailsAnnotation   = "k8lex.io/policy-violation-details"
	ConflictResolutionAnnotation = "k8lex.io/policy-conflicts"
	PolicyBypassAnnotation       = "k8lex.io/policy-bypass"
	EmergencyBypassAnnotation    = "k8lex.io/emergency-bypass"

	// Constants for reconcile behavior
	DefaultRequeueDelay = 30 * time.Second
	MaxRetries          = 5
	JQCacheMaxSize      = 1000

	// Retry and backoff constants
	MaxBackoffDelay   = 300 * time.Second // 5 minutes
	BaseBackoffDelay  = 1 * time.Second
	BackoffMultiplier = 2.0
	JitterMaxFactor   = 0.1

	// Circuit breaker constants
	CircuitBreakerThreshold = 5
	CircuitBreakerTimeout   = 60 * time.Second

	// Cache constants
	PolicyCacheTTL       = 5 * time.Minute
	PolicyEvalCacheTTL   = 2 * time.Minute
	JQCacheTTL           = 10 * time.Minute
	CacheCleanupInterval = 1 * time.Minute

	// Performance constants
	MaxConcurrentEvaluations = 10
	EvaluationTimeout        = 30 * time.Second
)

// Policy failure modes
type FailureMode string

const (
	FailSecure FailureMode = "fail-secure" // Block on failure
	FailSafe   FailureMode = "fail-safe"   // Allow on failure
)

// Circuit breaker state
type CircuitBreakerState int

const (
	CircuitClosed CircuitBreakerState = iota
	CircuitOpen
	CircuitHalfOpen
)

// Enhanced cache entry with TTL
type CacheEntry struct {
	Value       interface{}
	ExpiresAt   time.Time
	AccessCount int64
	LastAccess  time.Time
}

// LRU Cache with TTL
type LRUCache struct {
	mu       sync.RWMutex
	capacity int
	entries  map[string]*CacheEntry
	order    []string // LRU order
}

// Circuit breaker for API operations
type CircuitBreaker struct {
	mu           sync.RWMutex
	state        CircuitBreakerState
	failures     int
	lastFailTime time.Time
	timeout      time.Duration
	threshold    int
}

// Policy evaluation result cache entry
type PolicyEvalCacheEntry struct {
	ResourceVersion string
	PolicyVersion   string
	Result          []ValidationResult
	CachedAt        time.Time
}

// Enhanced retry configuration
type RetryConfig struct {
	MaxRetries      int
	BaseDelay       time.Duration
	MaxDelay        time.Duration
	Multiplier      float64
	JitterMaxFactor float64
}

// PolicyConflictResolution defines how to handle policy conflicts
type PolicyConflictResolution string

const (
	ConflictResolutionMostRestrictive PolicyConflictResolution = "most-restrictive"
	ConflictResolutionFirstMatch      PolicyConflictResolution = "first-match"
	ConflictResolutionHighestSeverity PolicyConflictResolution = "highest-severity"
)

// ResourceTypeConfig defines configuration for each resource type
type ResourceTypeConfig struct {
	GVK    schema.GroupVersionKind
	Object client.Object
}

// ValidationResult represents the outcome of a policy validation
type ValidationResult struct {
	PolicyName   string
	RuleName     string
	Violated     bool
	Action       string
	Severity     string
	ErrorMessage string
	ResourcePath string
	Priority     int // For conflict resolution
}

// ClusterPolicyValidatorReconciler reconciles a ClusterPolicyValidator object
type ClusterPolicyValidatorReconciler struct {
	client.Client
	Scheme           *runtime.Scheme
	WatchedResources []ResourceTypeConfig
	Log              logr.Logger
	EventRecorder    record.EventRecorder

	// Enhanced caching with LRU and TTL
	jqCache         *LRUCache
	policyEvalCache *LRUCache
	policyCache     *LRUCache

	// Circuit breakers for different operations
	apiCircuitBreaker    *CircuitBreaker
	policyCircuitBreaker *CircuitBreaker

	// Enhanced retry configuration
	retryConfig RetryConfig

	// Failure mode configuration
	FailureMode FailureMode

	// Rate limiting for policy evaluations
	policyEvalLimiter map[string]*time.Timer
	evalLimiterMu     sync.RWMutex

	// Namespace filtering state - per reconciler instead of global
	namespaceFilter   *NamespaceFilterState
	namespaceFilterMu sync.RWMutex

	// Conflict resolution strategy
	ConflictResolution PolicyConflictResolution

	// Semaphore for limiting concurrent evaluations
	evaluationSemaphore chan struct{}

	// Context for graceful shutdown
	shutdownCtx context.Context
	cancel      context.CancelFunc
}

// NamespaceFilterState holds the aggregated namespace filtering rules from all policies.
type NamespaceFilterState struct {
	IncludedNamespaces map[string]struct{}
	ExcludedNamespaces map[string]struct{}
	HasIncludeRules    bool
	HasExcludeRules    bool
	LastUpdated        time.Time
}
