package clusterpolicyvalidator

import (
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
	DefaultRequeueDelay          = 30 * time.Second
)

// PolicyConflictResolution defines how to handle policy conflicts
type PolicyConflictResolution string

const (
	ConflictResolutionMostRestrictive PolicyConflictResolution = "most-restrictive"
	ConflictResolutionFirstMatch      PolicyConflictResolution = "first-match"
)

// ValidationResult represents the outcome of a policy validation
type ValidationResult struct {
	PolicyName   string
	RuleName     string
	Violated     bool
	Action       string
	ErrorMessage string
	ResourcePath string
	Priority     int
	Notifier     string
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

	// Namespace filtering state - per reconciler instead of global
	namespaceFilter   *NamespaceFilterState
	namespaceFilterMu sync.RWMutex
}

// NamespaceFilterState holds the aggregated namespace filtering rules from all policies.
type NamespaceFilterState struct {
	IncludedNamespaces map[string]struct{}
	ExcludedNamespaces map[string]struct{}
	HasIncludeRules    bool
	HasExcludeRules    bool
	LastUpdated        time.Time
}

type NonRetryableError struct {
	Err error
}
