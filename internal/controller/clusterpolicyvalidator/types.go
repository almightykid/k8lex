package clusterpolicyvalidator

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/almightykid/k8lex/internal/controller/clusterpolicynotifier"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Constants for annotations
const (
	PolicyBlockedAnnotation      = "k8lex.io/policy-blocked"
	OriginalReplicasAnnotation   = "k8lex.io/original-replicas"
	BlockedReasonAnnotation      = "k8lex.io/blocked-reason"
	PolicyViolationAnnotation    = "k8lex.io/policy-violation"
	ViolationDetailsAnnotation   = "k8lex.io/policy-violation-details"
	ConflictResolutionAnnotation = "k8lex.io/policy-conflicts"
	PolicyBypassAnnotation       = "k8lex.io/policy-bypass"
	EmergencyBypassAnnotation    = "k8lex.io/emergency-bypass"
	LastNotificationAnnotation   = "k8lex.io/last-notification-time"
	DefaultRequeueDelay          = 30 * time.Second
	NotificationCooldownDuration = 5 * time.Minute

	// Security and robustness constants
	MaxJQResultsLimit    = 1000 // Maximum JQ query results to prevent resource exhaustion
	MaxAnnotationRetries = 5    // Maximum retries for annotation updates
	MaxLogValueLength    = 100  // Maximum length for logged values to prevent info disclosure
)

// PolicyConflictResolution defines how to handle policy conflicts
type PolicyConflictResolution string

const (
	ConflictResolutionMostRestrictive PolicyConflictResolution = "most-restrictive"
	ConflictResolutionFirstMatch      PolicyConflictResolution = "first-match"
)

// ValidationResult represents the outcome of a policy validation
type ValidationResult struct {
	PolicyName   string `json:"policy_name"`
	RuleName     string `json:"rule_name"`
	Violated     bool   `json:"violated"`
	Action       string `json:"action"`
	ErrorMessage string `json:"error_message,omitempty"`
	ResourcePath string `json:"resource_path"`
	Priority     int    `json:"priority"`
	Notifier     string `json:"notifier,omitempty"`
}

// String returns a JSON representation of the validation result for safe serialization
func (vr ValidationResult) String() string {
	data, err := json.Marshal(vr)
	if err != nil {
		return "ValidationResult{error: invalid data}"
	}
	return string(data)
}

// ClusterPolicyValidatorReconciler reconciles a ClusterPolicyValidator object
type ClusterPolicyValidatorReconciler struct {
	client.Client

	Scheme        *runtime.Scheme
	Log           logr.Logger
	EventRecorder record.EventRecorder

	// Conflict resolution strategy
	ConflictResolution PolicyConflictResolution

	// Notification service for policy violations
	NotifierController *clusterpolicynotifier.ClusterPolicyNotifierReconciler

	// Configuration for operational behavior
	Config *OperationalConfig

	// Namespace filtering state - per reconciler instead of global
	namespaceFilter   *NamespaceFilterState
	namespaceFilterMu sync.RWMutex

	// JQ query cache for performance optimization
	jqCache   sync.Map // map[string]*gojq.Code
	jqCacheMu sync.RWMutex
}

// NamespaceFilterState holds the aggregated namespace filtering rules from all policies.
type NamespaceFilterState struct {
	IncludedNamespaces map[string]struct{}
	ExcludedNamespaces map[string]struct{}
	HasIncludeRules    bool
	HasExcludeRules    bool
	LastUpdated        time.Time
	// Track policy generations for event-driven invalidation
	PolicyGenerations map[string]int64 // policy name -> generation
}

type NonRetryableError struct {
	Err error
}

// SecurityError represents a security-related error with structured error code
type SecurityError struct {
	Code    string
	Message string
	Cause   error
}

func (e SecurityError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("security error [%s]: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("security error [%s]: %s", e.Code, e.Message)
}

// Security error codes
const (
	ErrorCodeResourceExhaustion = "RESOURCE_EXHAUSTION"
	ErrorCodeInformationLeak    = "INFORMATION_LEAK"
	ErrorCodeRaceCondition      = "RACE_CONDITION"
	ErrorCodeInvalidInput       = "INVALID_INPUT"
)

// Configuration for operational behavior
type OperationalConfig struct {
	// Default notifier configuration
	DefaultNotifierName string        `json:"defaultNotifierName" yaml:"defaultNotifierName"`
	NotificationTimeout time.Duration `json:"notificationTimeout" yaml:"notificationTimeout"`
	NotificationRetries int           `json:"notificationRetries" yaml:"notificationRetries"`

	// Validation configuration
	ValidationTimeout        time.Duration `json:"validationTimeout" yaml:"validationTimeout"`
	MaxConcurrentValidations int           `json:"maxConcurrentValidations" yaml:"maxConcurrentValidations"`

	// Cache configuration
	CacheTTL        time.Duration `json:"cacheTTL" yaml:"cacheTTL"`
	MaxCacheEntries int           `json:"maxCacheEntries" yaml:"maxCacheEntries"`

	// Performance tuning
	RequeueDelay      time.Duration `json:"requeueDelay" yaml:"requeueDelay"`
	BackoffMultiplier float64       `json:"backoffMultiplier" yaml:"backoffMultiplier"`
}

// GetDefaultOperationalConfig returns the default operational configuration
func GetDefaultOperationalConfig() *OperationalConfig {
	return &OperationalConfig{
		DefaultNotifierName:      "slack-notifier",
		NotificationTimeout:      30 * time.Second,
		NotificationRetries:      3,
		ValidationTimeout:        60 * time.Second,
		MaxConcurrentValidations: 5,
		CacheTTL:                 30 * time.Minute,
		MaxCacheEntries:          1000,
		RequeueDelay:             DefaultRequeueDelay,
		BackoffMultiplier:        2.0,
	}
}
