package workflow

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestJournalAttemptTransitionsAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workflow.db")
	j, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	job, err := j.Begin(Job{ID: "job-1", Kind: "SIGN", RequestID: "req-1", KeyID: "wallet", Epoch: 1, AttemptID: "attempt-1", SessionID: "session-1", Digest: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	job, err = j.Transition(job.ID, job.Version, Running, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Transition(job.ID, 1, Signed, []byte("sig"), nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update should conflict, got %v", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	got, err := j.GetRequest("req-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != Interrupted || got.Version != 3 {
		t.Fatalf("running attempt not marked interrupted: %+v", got)
	}
	if _, err := j.Transition(got.ID, got.Version, Signed, nil, nil); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("interrupted attempt must not resume: %v", err)
	}
}

func TestJournalRequestUniquenessAndEpochFloor(t *testing.T) {
	j, err := Open(filepath.Join(t.TempDir(), "workflow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	base := Job{ID: "job-1", Kind: "SIGN", RequestID: "req", KeyID: "wallet", Epoch: 1, AttemptID: "a1", SessionID: "s1", Digest: make([]byte, 32)}
	if _, err := j.Begin(base); err != nil {
		t.Fatal(err)
	}
	base.ID = "job-2"
	base.AttemptID = "a2"
	base.SessionID = "s2"
	if _, err := j.Begin(base); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate request should conflict: %v", err)
	}
	manifest := make([]byte, 32)
	manifest[0] = 1
	if err := j.DecideEpochCommit("wallet", 2, manifest); err != nil {
		t.Fatal(err)
	}
	if epoch, err := j.MinimumEpoch("wallet"); err != nil || epoch != 2 {
		t.Fatalf("minimum epoch %d, err %v", epoch, err)
	}
	if err := j.DecideEpochCommit("wallet", 1, manifest); !errors.Is(err, ErrConflict) {
		t.Fatalf("epoch rollback accepted: %v", err)
	}
	if err := j.DecideEpochCommit("wallet", 2, manifest); err != nil {
		t.Fatalf("identical commit must be idempotent: %v", err)
	}
	manifest[0] = 2
	if err := j.DecideEpochCommit("wallet", 2, manifest); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting manifest accepted: %v", err)
	}
}

func TestOnlyCommittedCurrentEpochCanSign(t *testing.T) {
	j, err := Open(filepath.Join(t.TempDir(), "workflow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	job, err := j.Begin(Job{ID: "dkg1", Kind: "DKG", KeyID: "wallet", Epoch: 1, AttemptID: "a1", SessionID: "s1"})
	if err != nil {
		t.Fatal(err)
	}
	job, err = j.Transition(job.ID, job.Version, Running, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	job, err = j.Transition(job.ID, job.Version, Ready, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	manifest := make([]byte, 32)
	manifest[0] = 1
	if err = j.DecideEpochCommit("wallet", 1, manifest); err != nil {
		t.Fatal(err)
	}
	job, err = j.Transition(job.ID, job.Version, Active, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := j.CanSign("wallet", 1); err != nil || !ok {
		t.Fatalf("active committed epoch cannot sign: %v %v", ok, err)
	}
	manifest[0] = 2
	if err = j.DecideEpochCommit("wallet", 2, manifest); err != nil {
		t.Fatal(err)
	}
	if ok, err := j.CanSign("wallet", 1); err != nil || ok {
		t.Fatalf("historical epoch remained signable: %v %v", ok, err)
	}
	if ok, err := j.CanSign("wallet", 2); err != nil || ok {
		t.Fatalf("unactivated epoch became signable: %v %v", ok, err)
	}
}
