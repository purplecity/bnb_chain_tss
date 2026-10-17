// Package workflow stores durable operation and epoch state. Protocol memory
// state is deliberately discarded after a process restart; callers create a
// fresh attempt ID after an interrupted attempt.
package workflow

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	ErrConflict          = errors.New("workflow state conflict")
	ErrInvalidTransition = errors.New("invalid workflow state transition")
)

type Status string

const (
	Queued      Status = "QUEUED"
	Running     Status = "RUNNING"
	Ready       Status = "READY"
	Active      Status = "ACTIVE"
	Signed      Status = "SIGNED"
	Broadcast   Status = "BROADCAST"
	Complete    Status = "COMPLETE"
	Failed      Status = "FAILED"
	Interrupted Status = "INTERRUPTED"
)

type Job struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	RequestID string    `json:"request_id,omitempty"`
	KeyID     string    `json:"key_id"`
	Epoch     uint64    `json:"epoch"`
	AttemptID string    `json:"attempt_id"`
	SessionID string    `json:"session_id"`
	Digest    []byte    `json:"digest,omitempty"`
	Status    Status    `json:"status"`
	Version   uint64    `json:"version"`
	Result    []byte    `json:"result,omitempty"`
	Error     string    `json:"error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Journal struct{ db *bolt.DB }

var jobsBucket = []byte("jobs-v1")
var requestsBucket = []byte("requests-v1")
var epochsBucket = []byte("minimum-epochs-v1")
var commitsBucket = []byte("commit-decisions-v1")

func Open(path string) (*Journal, error) {
	if path == "" {
		return nil, errors.New("workflow journal path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create workflow journal directory: %w", err)
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	j := &Journal{db: db}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{jobsBucket, requestsBucket, epochsBucket, commitsBucket} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	if err := j.markInterrupted(); err != nil {
		db.Close()
		return nil, err
	}
	return j, nil
}

func (j *Journal) Close() error { return j.db.Close() }

// Begin writes the attempt record durably before a caller sends its first TSS
// protocol message. Reuse of an attempt or job ID is rejected.
func (j *Journal) Begin(job Job) (Job, error) {
	if job.ID == "" || job.Kind == "" || job.KeyID == "" || job.Epoch == 0 || job.AttemptID == "" || job.SessionID == "" {
		return Job{}, errors.New("incomplete workflow job")
	}
	if job.Status != "" && job.Status != Queued {
		return Job{}, errors.New("new workflow job must start queued")
	}
	if len(job.Digest) > 0 && len(job.Digest) != 32 {
		return Job{}, errors.New("workflow digest must be 32 bytes")
	}
	now := time.Now().UTC()
	job.Status = Queued
	job.Version = 1
	job.CreatedAt = now
	job.UpdatedAt = now
	encoded, err := json.Marshal(job)
	if err != nil {
		return Job{}, err
	}
	err = j.db.Update(func(tx *bolt.Tx) error {
		jobs := tx.Bucket(jobsBucket)
		if jobs.Get([]byte(job.ID)) != nil {
			return ErrConflict
		}
		requests := tx.Bucket(requestsBucket)
		if job.RequestID != "" {
			if old := requests.Get([]byte(job.RequestID)); old != nil {
				var prior Job
				if err := json.Unmarshal(old, &prior); err != nil {
					return err
				}
				if prior.KeyID != job.KeyID || prior.Epoch != job.Epoch || !equalBytes(prior.Digest, job.Digest) {
					return ErrConflict
				}
				return ErrConflict
			}
			if err := requests.Put([]byte(job.RequestID), encoded); err != nil {
				return err
			}
		}
		return jobs.Put([]byte(job.ID), encoded)
	})
	return job, err
}

func (j *Journal) Transition(id string, expectedVersion uint64, next Status, result []byte, operationErr error) (Job, error) {
	var updated Job
	err := j.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(jobsBucket)
		raw := bucket.Get([]byte(id))
		if raw == nil {
			return os.ErrNotExist
		}
		var job Job
		if err := json.Unmarshal(raw, &job); err != nil {
			return err
		}
		if job.Version != expectedVersion {
			return ErrConflict
		}
		if !allowed(job.Status, next) {
			return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, job.Status, next)
		}
		job.Status = next
		job.Version++
		job.UpdatedAt = time.Now().UTC()
		job.Result = append([]byte(nil), result...)
		if operationErr != nil {
			job.Error = operationErr.Error()
		}
		encoded, err := json.Marshal(job)
		if err != nil {
			return err
		}
		if err := bucket.Put([]byte(id), encoded); err != nil {
			return err
		}
		if job.RequestID != "" {
			if err := tx.Bucket(requestsBucket).Put([]byte(job.RequestID), encoded); err != nil {
				return err
			}
		}
		updated = job
		return nil
	})
	return updated, err
}

func (j *Journal) Get(id string) (Job, error) {
	var job Job
	err := j.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(jobsBucket).Get([]byte(id))
		if raw == nil {
			return os.ErrNotExist
		}
		return json.Unmarshal(raw, &job)
	})
	return job, err
}

func (j *Journal) GetRequest(requestID string) (Job, error) {
	var job Job
	err := j.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(requestsBucket).Get([]byte(requestID))
		if raw == nil {
			return os.ErrNotExist
		}
		return json.Unmarshal(raw, &job)
	})
	return job, err
}

func (j *Journal) MinimumEpoch(keyID string) (uint64, error) {
	var epoch uint64
	err := j.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(epochsBucket).Get([]byte(keyID))
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &epoch)
	})
	return epoch, err
}

func (j *Journal) HasActiveKey(keyID string, epoch uint64) (bool, error) {
	found := false
	err := j.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(jobsBucket).ForEach(func(_, value []byte) error {
			var job Job
			if err := json.Unmarshal(value, &job); err != nil {
				return err
			}
			if job.Kind == "DKG" && job.KeyID == keyID && job.Epoch == epoch && job.Status == Active {
				found = true
			}
			return nil
		})
	})
	return found, err
}

// CanSign returns true only for the currently committed epoch, never for a
// historical job that still carries an ACTIVE status after a later commit.
func (j *Journal) CanSign(keyID string, epoch uint64) (bool, error) {
	allowed := false
	err := j.db.View(func(tx *bolt.Tx) error {
		var floor uint64
		if raw := tx.Bucket(epochsBucket).Get([]byte(keyID)); raw != nil {
			if err := json.Unmarshal(raw, &floor); err != nil {
				return err
			}
		}
		if floor != epoch {
			return nil
		}
		return tx.Bucket(jobsBucket).ForEach(func(_, value []byte) error {
			var job Job
			if err := json.Unmarshal(value, &job); err != nil {
				return err
			}
			if job.Kind == "DKG" && job.KeyID == keyID && job.Epoch == epoch && job.Status == Active {
				allowed = true
			}
			return nil
		})
	})
	return allowed, err
}

// DecideEpochCommit durably raises the epoch floor. Once committed, callers
// must finish activating that epoch; this journal never supports rollback.
func (j *Journal) DecideEpochCommit(keyID string, epoch uint64, manifestHash []byte) error {
	if keyID == "" || epoch == 0 || len(manifestHash) != 32 {
		return errors.New("invalid epoch commit decision")
	}
	return j.db.Update(func(tx *bolt.Tx) error {
		epochs := tx.Bucket(epochsBucket)
		var current uint64
		if raw := epochs.Get([]byte(keyID)); raw != nil {
			if err := json.Unmarshal(raw, &current); err != nil {
				return err
			}
		}
		if epoch < current {
			return ErrConflict
		}
		if epoch == current {
			stored := tx.Bucket(commitsBucket).Get(commitKey(keyID, epoch))
			if equalBytes(stored, manifestHash) {
				return nil
			}
			return ErrConflict
		}
		epochBytes, _ := json.Marshal(epoch)
		if err := epochs.Put([]byte(keyID), epochBytes); err != nil {
			return err
		}
		return tx.Bucket(commitsBucket).Put(commitKey(keyID, epoch), manifestHash)
	})
}

func (j *Journal) markInterrupted() error {
	return j.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(jobsBucket).ForEach(func(key, value []byte) error {
			var job Job
			if err := json.Unmarshal(value, &job); err != nil {
				return err
			}
			if job.Status != Running {
				return nil
			}
			job.Status = Interrupted
			job.Version++
			job.UpdatedAt = time.Now().UTC()
			job.Error = "process restarted; protocol memory state was discarded"
			encoded, err := json.Marshal(job)
			if err != nil {
				return err
			}
			if err := tx.Bucket(jobsBucket).Put(key, encoded); err != nil {
				return err
			}
			if job.RequestID != "" {
				return tx.Bucket(requestsBucket).Put([]byte(job.RequestID), encoded)
			}
			return nil
		})
	})
}

func allowed(from, to Status) bool {
	switch from {
	case Queued:
		return to == Running || to == Failed
	case Running:
		return to == Ready || to == Signed || to == Failed || to == Interrupted
	case Ready:
		return to == Active || to == Failed
	case Active:
		return to == Broadcast || to == Complete
	case Signed:
		return to == Broadcast || to == Complete
	case Broadcast:
		return to == Complete
	}
	return false
}
func commitKey(keyID string, epoch uint64) []byte {
	return []byte(fmt.Sprintf("%s:%020d", keyID, epoch))
}
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
