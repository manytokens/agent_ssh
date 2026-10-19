package execsvc

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

const jobRetention = 7 * 24 * time.Hour
const jobHistoryLimit = 100

func completedJob(t *task) bool {
	if t.kind != "job" {
		return false
	}
	select {
	case <-t.done:
		return true
	default:
		return false
	}
}

// Call while holding s.mu. Completion closes done only after persistence and
// file closure, so cleanup can never delete an active writer's directory.
func (s *Service) removeJobLocked(t *task, dry bool) error {
	if !completedJob(t) {
		return fmt.Errorf("job %s is still running", t.id)
	}
	if dry {
		return nil
	}
	t.logMu.Lock()
	defer t.logMu.Unlock()
	if t.logDir != "" {
		if err := os.RemoveAll(t.logDir); err != nil {
			return err
		}
	}
	delete(s.tasks, t.id)
	return nil
}

func (s *Service) pruneJobs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	var jobs []*task
	for _, t := range s.tasks {
		if completedJob(t) {
			jobs = append(jobs, t)
		}
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].finished.After(jobs[j].finished) })
	cutoff := time.Now().Add(-jobRetention)
	for i, t := range jobs {
		if i >= jobHistoryLimit || t.finished.Before(cutoff) {
			_ = s.removeJobLocked(t, false)
		}
	}
}

func (s *Service) maintainJobs() {
	defer s.wg.Done()
	tick := time.NewTicker(5 * time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-tick.C:
			s.pruneJobs()
		}
	}
}

// manageJobs handles job clean/remove before the common task argument parser.
func (s *Service) manageJobs(args []string, out io.Writer) error {
	action := args[0]
	var id string
	var older time.Duration
	dry := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--json":
		case "--dry-run":
			dry = true
		case "--older-than":
			if action != "clean" {
				return fmt.Errorf("--older-than is only supported by job clean")
			}
			i++
			if i >= len(args) {
				return fmt.Errorf("--older-than requires a duration")
			}
			var err error
			older, err = time.ParseDuration(args[i])
			if err != nil || older < 0 {
				return fmt.Errorf("invalid --older-than duration")
			}
		default:
			if strings.HasPrefix(args[i], "-") || action != "remove" || id != "" {
				return fmt.Errorf("unexpected job %s argument: %s", action, args[i])
			}
			id = args[i]
		}
	}
	if action == "remove" && id == "" {
		return fmt.Errorf("job remove requires an ID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := []string{}
	if action == "remove" {
		t := s.tasks[id]
		if t == nil || t.kind != "job" {
			return fmt.Errorf("unknown job ID")
		}
		if err := s.removeJobLocked(t, dry); err != nil {
			return err
		}
		ids = append(ids, id)
	} else {
		cutoff := time.Now().Add(-older)
		for _, t := range s.tasks {
			if completedJob(t) && !t.finished.After(cutoff) {
				if err := s.removeJobLocked(t, dry); err != nil {
					return err
				}
				ids = append(ids, t.id)
			}
		}
	}
	sort.Strings(ids)
	return jsonOut(out, map[string]any{"dry_run": dry, "removed": ids, "count": len(ids)})
}
