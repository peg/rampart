package proxy

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRecordDecisionIncrementsCounter(t *testing.T) {
	decisionsTotal.Reset()

	RecordDecision("allow", "test-policy", 50*time.Microsecond)
	RecordDecision("deny", "test-policy", 100*time.Microsecond)
	RecordDecision("allow", "test-policy", 30*time.Microsecond)

	val := testutil.ToFloat64(decisionsTotal.WithLabelValues("allow", "test-policy"))
	if val != 2 {
		t.Errorf("expected allow count 2, got %v", val)
	}

	val = testutil.ToFloat64(decisionsTotal.WithLabelValues("deny", "test-policy"))
	if val != 1 {
		t.Errorf("expected deny count 1, got %v", val)
	}
}

func TestRecordDecisionEmptyPolicy(t *testing.T) {
	decisionsTotal.Reset()

	RecordDecision("log", "", 10*time.Microsecond)

	val := testutil.ToFloat64(decisionsTotal.WithLabelValues("log", "none"))
	if val != 1 {
		t.Errorf("expected log/none count 1, got %v", val)
	}
}

func TestSetPendingApprovals(t *testing.T) {
	SetPendingApprovals(5)
	val := testutil.ToFloat64(pendingApprovals)
	if val != 5 {
		t.Errorf("expected 5, got %v", val)
	}
}

func TestSetPolicyCount(t *testing.T) {
	SetPolicyCount(10)
	val := testutil.ToFloat64(policyCount)
	if val != 10 {
		t.Errorf("expected 10, got %v", val)
	}
}
