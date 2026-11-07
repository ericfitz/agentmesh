package bus

import (
	"context"
	"fmt"
	"strings"
	"testing"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/dbtest"
	ab2store "github.com/ericfitz/agentmesh/internal/store"
)

func boundsRep(s string, n int) string { return strings.Repeat(s, n) }

func boundsKeys(n int) map[string]string {
	m := make(map[string]string, n)
	for i := range n {
		m[fmt.Sprintf("k%02d", i)] = "v"
	}
	return m
}

func boundsTags(n int) []string {
	out := make([]string, n)
	for i := range n {
		out[i] = fmt.Sprintf("t%d", i)
	}
	return out
}

func boundsIDs(n int) []int64 {
	out := make([]int64, n)
	for i := range n {
		out[i] = int64(i + 1)
	}
	return out
}

func boundsPtr[T any](v T) *T { return &v }

// TestOverBoundRefused sends each request one over its bound and expects
// validation. text, the core's own wording, is asserted on the local
// transport only: on inproc the validator may answer first with its own text.
func TestOverBoundRefused(t *testing.T) {
	dbtest.ForEachEngine(t, func(t *testing.T, e dbtest.Engine) {
		h := newHarness(t, e, harnessOptions{})
		h.channel("dev", ab2store.KindOrdinary, "pat", nil)
		mem := h.channel("mem", ab2store.KindMemory, "pat", nil)
		h.channel("work", ab2store.KindTasks, "pat", nil)
		memID := h.append(mem, "pat", "", "hello")
		sess := h.session("pat", "pat/impl")
		b := h.as("pat")
		ctx := context.Background()
		sid := sess.ID
		// A task carrying 16 metadata keys, for the merged-patch case.
		task16, err := b.Create(ctx, ab2bus.TaskCreateInput{Channel: "work", Subject: "t", Metadata: boundsKeys(16)})
		if err != nil {
			t.Fatal(err)
		}
		over := h.cfg.MaxMessageKiB*1024 + 1

		type c struct {
			name string
			call func(ctx context.Context, b ab2bus.Bus) error
			text string
		}
		send := func(in ab2bus.SendInput) func(context.Context, ab2bus.Bus) error {
			if in.Channel == "" {
				in.Channel = "dev"
			}
			if in.Content == "" {
				in.Content = "x"
			}
			return func(ctx context.Context, b ab2bus.Bus) error { _, err := b.Send(ctx, in); return err }
		}
		history := func(in ab2bus.HistoryInput) func(context.Context, ab2bus.Bus) error {
			in.Channel = "dev"
			return func(ctx context.Context, b ab2bus.Bus) error { _, err := b.History(ctx, in); return err }
		}
		search := func(in ab2bus.SearchInput) func(context.Context, ab2bus.Bus) error {
			if in.Query == "" {
				in.Query = "hello"
			}
			return func(ctx context.Context, b ab2bus.Bus) error { _, err := b.Search(ctx, in); return err }
		}
		receive := func(in ab2bus.ReceiveInput) func(context.Context, ab2bus.Bus) error {
			if in.Session == "" {
				in.Session = sid
			}
			return func(ctx context.Context, b ab2bus.Bus) error { _, err := b.Receive(ctx, in); return err }
		}
		edit := func(in ab2bus.EditMemoryInput) func(context.Context, ab2bus.Bus) error {
			in.ID = memID
			return func(ctx context.Context, b ab2bus.Bus) error { _, err := b.Edit(ctx, in); return err }
		}
		create := func(in ab2bus.TaskCreateInput) func(context.Context, ab2bus.Bus) error {
			in.Channel = "work"
			if in.Subject == "" {
				in.Subject = "s"
			}
			return func(ctx context.Context, b ab2bus.Bus) error { _, err := b.Create(ctx, in); return err }
		}
		update := func(p ab2bus.TaskPatch) func(context.Context, ab2bus.Bus) error {
			if p.ID == 0 {
				p.ID = task16.ID
			}
			return func(ctx context.Context, b ab2bus.Bus) error { _, err := b.Update(ctx, p); return err }
		}
		status := func(in ab2bus.SetAgentStatusInput) func(context.Context, ab2bus.Bus) error {
			in.Session = sid
			if in.Tag == "" {
				in.Tag = ab2bus.StatusTag("idle")
			}
			if in.Text == "" {
				in.Text = "working"
			}
			return func(ctx context.Context, b ab2bus.Bus) error { _, err := b.SetAgentStatus(ctx, in); return err }
		}
		acl := func(n int) []ab2bus.ACLEntry {
			out := make([]ab2bus.ACLEntry, n)
			for i := range n {
				out[i] = ab2bus.ACLEntry{Identity: fmt.Sprintf("u%d", i), Permissions: []ab2bus.Permission{"read"}}
			}
			return out
		}
		long := func(n int) string { return boundsRep("a", n) }

		cases := []c{
			{"session_id_bytes", receive(ab2bus.ReceiveInput{Session: long(1025)}), "at most 1024 bytes"},
			{"open_cursors_items", func(ctx context.Context, b ab2bus.Bus) error {
				cs := make([]ab2bus.OfferedCursor, 257)
				for i := range cs {
					cs[i] = ab2bus.OfferedCursor{Channel: fmt.Sprintf("c%d", i)}
				}
				_, err := b.Open(ctx, ab2bus.OpenSessionInput{Cursors: cs})
				return err
			}, "at most 256"},
			{"open_cursor_channel_bytes", func(ctx context.Context, b ab2bus.Bus) error {
				_, err := b.Open(ctx, ab2bus.OpenSessionInput{Cursors: []ab2bus.OfferedCursor{{Channel: long(129)}}})
				return err
			}, "1-128 bytes"},
			{"open_cursor_seq_negative", func(ctx context.Context, b ab2bus.Bus) error {
				_, err := b.Open(ctx, ab2bus.OpenSessionInput{Cursors: []ab2bus.OfferedCursor{{Channel: "dev", Seq: -1}}})
				return err
			}, "must not be negative"},
			{"open_resume_token_shape", func(ctx context.Context, b ab2bus.Bus) error {
				_, err := b.Open(ctx, ab2bus.OpenSessionInput{ResumeToken: long(44)})
				return err
			}, "malformed"},
			{"receive_ack_bytes", receive(ab2bus.ReceiveInput{Ack: long(1025)}), "at most 1024 bytes"},
			{"receive_channels_items", receive(ab2bus.ReceiveInput{Channels: boundsTags(257)}), "at most 256"},
			{"receive_count_ceiling", receive(ab2bus.ReceiveInput{Count: 10001}), "at most 10000"},
			{"watch_timeout_ceiling", func(ctx context.Context, b ab2bus.Bus) error {
				_, err := b.Watch(ctx, ab2bus.WatchInput{Session: sid, Timeout: 241 * 1e9})
				return err
			}, "at most 240 seconds"},
			{"watch_after_negative", func(ctx context.Context, b ab2bus.Bus) error {
				_, err := b.Watch(ctx, ab2bus.WatchInput{Session: sid, After: -1})
				return err
			}, "must not be negative"},
			{"send_subject_runes", send(ab2bus.SendInput{Subject: boundsRep("a", 201)}), "at most 200 characters"},
			{"send_subject_padded", send(ab2bus.SendInput{Subject: boundsRep("a", 200) + " "}), "at most 200 characters"},
			{"send_type_runes", send(ab2bus.SendInput{Type: boundsRep("a", 257)}), "at most 256 characters"},
			{"send_metadata_keys", send(ab2bus.SendInput{Metadata: boundsKeys(33)}), "at most 32"},
			{"send_metadata_key_runes", send(ab2bus.SendInput{Metadata: map[string]string{boundsRep("k", 65): "v"}}), "at most 64 characters"},
			{"send_metadata_value_runes", send(ab2bus.SendInput{Metadata: map[string]string{"k": boundsRep("v", 1025)}}), "at most 1024 characters"},
			{"send_tags_items", send(ab2bus.SendInput{Tags: boundsTags(11)}), "at most 10 tags"},
			{"send_tags_duplicates", send(ab2bus.SendInput{Tags: append(boundsTags(10), "t0")}), "at most 10 tags"},
			{"send_tag_len", send(ab2bus.SendInput{Tags: []string{long(33)}}), "1-32 characters"},
			{"send_reply_to_negative", send(ab2bus.SendInput{ReplyTo: boundsPtr(int64(-1))}), "must not be negative"},
			{"send_session_bytes", send(ab2bus.SendInput{Session: long(1025)}), "at most 1024 bytes"},
			{"history_count_ceiling", history(ab2bus.HistoryInput{Count: 10001}), "at most 10000"},
			{"history_after_negative", history(ab2bus.HistoryInput{After: boundsPtr(int64(-1))}), "must not be negative"},
			{"history_tags_items", history(ab2bus.HistoryInput{Tags: boundsTags(11)}), ""},
			{"history_pattern_len", history(ab2bus.HistoryInput{Tags: []string{long(34)}}), ""},
			{"search_query_runes", search(ab2bus.SearchInput{Query: boundsRep("a", 1025)}), "at most 1024 characters"},
			{"search_count_ceiling", search(ab2bus.SearchInput{Count: 1001}), "at most 1000"},
			{"search_cursor_len", search(ab2bus.SearchInput{Cursor: boundsRep("9", 20)}), "invalid cursor"},
			{"search_since_negative", search(ab2bus.SearchInput{Since: boundsPtr(int64(-1))}), "must not be negative"},
			{"search_thread_zero", search(ab2bus.SearchInput{Thread: boundsPtr(int64(0))}), "at least 1"},
			{"search_channel_bytes", search(ab2bus.SearchInput{Channel: long(129)}), "1-128 bytes"},
			{"edit_memory_type_runes", edit(ab2bus.EditMemoryInput{Type: boundsPtr(boundsRep("a", 257))}), "at most 256 characters"},
			{"edit_memory_metadata_keys", edit(ab2bus.EditMemoryInput{Metadata: boundsPtr(boundsKeys(33))}), "at most 32"},
			{"edit_memory_subject_runes", edit(ab2bus.EditMemoryInput{Subject: boundsPtr(boundsRep("a", 201))}), "at most 200 characters"},
			{"memory_id_negative", func(ctx context.Context, b ab2bus.Bus) error { _, err := b.GetMemory(ctx, -1); return err }, "must not be negative"},
			{"task_subject_runes", create(ab2bus.TaskCreateInput{Subject: boundsRep("a", 257)}), "1-256 characters"},
			{"task_subject_empty", func(ctx context.Context, b ab2bus.Bus) error {
				_, err := b.Create(ctx, ab2bus.TaskCreateInput{Channel: "work"})
				return err
			}, "1-256 characters"},
			{"task_description_envelope", create(ab2bus.TaskCreateInput{Description: boundsRep("d", over)}), ""},
			{"task_metadata_keys", create(ab2bus.TaskCreateInput{Metadata: boundsKeys(33)}), "at most 32"},
			{"task_patch_metadata_merged", update(ab2bus.TaskPatch{Metadata: func() map[string]string {
				m := map[string]string{}
				for i := range 17 {
					m[fmt.Sprintf("n%02d", i)] = "v"
				}
				return m
			}()}), "at most 32"},
			{"task_blockers_items", create(ab2bus.TaskCreateInput{BlockedBy: boundsIDs(65)}), "at most 64"},
			{"task_blockers_duplicates", create(ab2bus.TaskCreateInput{BlockedBy: append(boundsIDs(64), 1)}), "at most 64"},
			{"task_parent_negative", create(ab2bus.TaskCreateInput{Parent: -1}), "must not be negative"},
			{"task_id_negative", func(ctx context.Context, b ab2bus.Bus) error { _, err := b.GetTask(ctx, -1); return err }, "must not be negative"},
			{"task_leased_until_negative", update(ab2bus.TaskPatch{LeasedUntil: boundsPtr(int64(-1))}), "must not be negative"},
			{"task_owner_bytes", update(ab2bus.TaskPatch{Owner: boundsPtr(long(129))}), "1-128 bytes"},
			{"task_status_runes", update(ab2bus.TaskPatch{Status: boundsPtr(boundsRep("s", 257))}), "at most 256 characters"},
			{"list_tasks_owner_bytes", func(ctx context.Context, b ab2bus.Bus) error {
				_, err := b.List(ctx, ab2bus.TaskListInput{Channel: "work", Owner: long(129)})
				return err
			}, "1-128 bytes"},
			{"create_channel_acl_items", func(ctx context.Context, b ab2bus.Bus) error {
				_, err := b.CreateChannel(ctx, ab2bus.CreateChannelInput{Name: "acl1", ACL: acl(257)})
				return err
			}, "at most 256"},
			{"acl_permissions_items", func(ctx context.Context, b ab2bus.Bus) error {
				_, err := b.CreateChannel(ctx, ab2bus.CreateChannelInput{Name: "acl2", ACL: []ab2bus.ACLEntry{{Identity: "everyone", Permissions: []ab2bus.Permission{"read", "read", "read", "read"}}}})
				return err
			}, "at most 3 permissions per ACL entry"},
			{"acl_identity_bytes", func(ctx context.Context, b ab2bus.Bus) error {
				_, err := b.CreateChannel(ctx, ab2bus.CreateChannelInput{Name: "acl3", ACL: []ab2bus.ACLEntry{{Identity: long(129), Permissions: []ab2bus.Permission{"read"}}}})
				return err
			}, "1-128 bytes"},
			{"create_channel_name_bytes", func(ctx context.Context, b ab2bus.Bus) error {
				_, err := b.CreateChannel(ctx, ab2bus.CreateChannelInput{Name: long(129)})
				return err
			}, "1-128 bytes"},
			{"rename_name_bytes", func(ctx context.Context, b ab2bus.Bus) error {
				return b.RenameChannel(ctx, ab2bus.RenameChannelInput{Name: "dev", NewName: long(129)})
			}, "1-128 bytes"},
			{"subscribe_tags_items", func(ctx context.Context, b ab2bus.Bus) error {
				return b.SubscribeTags(ctx, ab2bus.TagSubscribeInput{Patterns: boundsTags(11)})
			}, ""},
			{"subscribe_tags_pattern_len", func(ctx context.Context, b ab2bus.Bus) error {
				return b.SubscribeTags(ctx, ab2bus.TagSubscribeInput{Patterns: []string{long(34)}})
			}, ""},
			{"status_text_runes", status(ab2bus.SetAgentStatusInput{Text: boundsRep("a", 201)}), "at most 200 characters"},
			{"status_problem_runes", status(ab2bus.SetAgentStatusInput{Problem: boundsRep("a", 201)}), "at most 200 characters"},
			{"status_tag_runes", status(ab2bus.SetAgentStatusInput{Tag: ab2bus.StatusTag(boundsRep("t", 257))}), "at most 256 characters"},
			{"status_history_identity_bytes", func(ctx context.Context, b ab2bus.Bus) error {
				_, err := b.AgentStatusHistory(ctx, long(129))
				return err
			}, "1-128 bytes"},
			{"idempotency_key_bytes", func(ctx context.Context, b ab2bus.Bus) error {
				_, err := b.CreateChannel(ctx, ab2bus.CreateChannelInput{Name: "idem", IdempotencyKey: long(1025)})
				return err
			}, "at most 1024 bytes"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				err := tc.call(ctx, b)
				if err == nil {
					t.Fatalf("%s: accepted, want validation", tc.name)
				}
				codeOf(t, err, ab2bus.CodeValidation)
				if transport == "local" && tc.text != "" && !strings.Contains(err.Error(), tc.text) {
					t.Fatalf("%s: error %q does not contain %q", tc.name, err, tc.text)
				}
			})
		}
	})
}

// TestRuneCountsAgree sends values that are within their bound in code points
// but over it in bytes: the validator counts code points and the core counts
// runes, so both transports accept them.
func TestRuneCountsAgree(t *testing.T) {
	dbtest.ForEachEngine(t, func(t *testing.T, e dbtest.Engine) {
		h := newHarness(t, e, harnessOptions{})
		h.channel("dev", ab2store.KindOrdinary, "pat", nil)
		h.channel("work", ab2store.KindTasks, "pat", nil)
		b := h.as("pat")
		ctx := context.Background()
		two := func(n int) string { return boundsRep("é", n) }
		t.Run("send", func(t *testing.T) {
			_, err := b.Send(ctx, ab2bus.SendInput{
				Channel: "dev", Content: "x", Subject: two(200), Type: two(256),
				Metadata: map[string]string{"k": two(1024)},
			})
			if err != nil {
				t.Fatal(err)
			}
		})
		t.Run("create_task", func(t *testing.T) {
			if _, err := b.Create(ctx, ab2bus.TaskCreateInput{Channel: "work", Subject: two(256)}); err != nil {
				t.Fatal(err)
			}
		})
	})
}
