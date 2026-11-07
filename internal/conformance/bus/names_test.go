package bus

import (
	"context"
	"testing"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/dbtest"
)

// Legal but awkward channel names must survive the generated client's path
// escaping and the server's binding unchanged (Review Focus 7, choice 17).
// The same assertions run under local (no wire) and inproc (the wire).
func TestChannelNameRoundTripsOnTheWire(t *testing.T) {
	dbtest.ForEachEngine(t, func(t *testing.T, e dbtest.Engine) {
		h := newHarness(t, e, harnessOptions{})
		ctx := context.Background()
		pat := h.as("pat")

		for _, name := range []string{"odd name", "100%", "a%2Fb", "what?", "tag#1", "c++", "café"} {
			t.Run(name, func(t *testing.T) {
				if _, err := pat.CreateChannel(ctx, ab2bus.CreateChannelInput{Name: name}); err != nil {
					t.Fatalf("CreateChannel: %v", err)
				}
				if err := pat.Subscribe(ctx, ab2bus.SubscribeInput{Channel: name}); err != nil {
					t.Fatalf("Subscribe: %v", err)
				}
				acl, err := pat.ACL(ctx, name)
				if err != nil {
					t.Fatalf("ACL: %v", err)
				}
				if err := pat.SetACL(ctx, ab2bus.SetACLInput{Channel: name, Entries: acl}); err != nil {
					t.Fatalf("SetACL: %v", err)
				}
				other := name + "-2"
				if err := pat.RenameChannel(ctx, ab2bus.RenameChannelInput{Name: name, NewName: other}); err != nil {
					t.Fatalf("Rename to %q: %v", other, err)
				}
				if err := pat.RenameChannel(ctx, ab2bus.RenameChannelInput{Name: other, NewName: name}); err != nil {
					t.Fatalf("Rename back: %v", err)
				}
				sent, err := pat.Send(ctx, ab2bus.SendInput{Channel: name, Content: "hello " + name})
				if err != nil {
					t.Fatalf("Send: %v", err)
				}
				hist, err := pat.History(ctx, ab2bus.HistoryInput{Channel: name})
				if err != nil {
					t.Fatalf("History: %v", err)
				}
				if len(hist) != 1 || hist[0].Seq != sent.Seq || hist[0].Content != "hello "+name {
					t.Fatalf("History = %+v, want the one message at seq %d", hist, sent.Seq)
				}
				chs, err := pat.ListChannels(ctx)
				if err != nil {
					t.Fatalf("ListChannels: %v", err)
				}
				seen := false
				for _, c := range chs {
					if c.Name == name {
						seen = true
					}
				}
				if !seen {
					t.Fatalf("ListChannels lacks %q: %+v", name, chs)
				}
				if err := pat.Unsubscribe(ctx, ab2bus.UnsubscribeInput{Channel: name}); err != nil {
					t.Fatalf("Unsubscribe: %v", err)
				}
				if err := pat.DeleteChannel(ctx, ab2bus.DeleteChannelInput{Name: name}); err != nil {
					t.Fatalf("DeleteChannel: %v", err)
				}
				// Gone: the name now resolves to nothing.
				if err := pat.Subscribe(ctx, ab2bus.SubscribeInput{Channel: name}); ab2bus.CodeOf(err) != ab2bus.CodeNotFound {
					t.Fatalf("Subscribe after delete = %v, want not_found", err)
				}
			})
		}

		// Names no path can carry. The core's name rule refuses them before
		// any lookup, so validation from every operation that takes the name
		// (issue #34); the one exception is the empty name on the wire, where
		// the empty path segment is the router's 404 (not_found), and Send,
		// whose empty channel is the required-field validation either way.
		for _, name := range []string{"", "a/b"} {
			t.Run("unaddressable "+name, func(t *testing.T) {
				want := ab2bus.CodeValidation
				if name == "" && transport == "inproc" {
					want = ab2bus.CodeNotFound
				}
				if err := pat.Subscribe(ctx, ab2bus.SubscribeInput{Channel: name}); ab2bus.CodeOf(err) != want {
					t.Errorf("Subscribe = %v, want %s", err, want)
				}
				if _, err := pat.ACL(ctx, name); ab2bus.CodeOf(err) != want {
					t.Errorf("ACL = %v, want %s", err, want)
				}
				if err := pat.DeleteChannel(ctx, ab2bus.DeleteChannelInput{Name: name}); ab2bus.CodeOf(err) != want {
					t.Errorf("DeleteChannel = %v, want %s", err, want)
				}
				if _, err := pat.Send(ctx, ab2bus.SendInput{Channel: name, Content: "x"}); ab2bus.CodeOf(err) != ab2bus.CodeValidation {
					t.Errorf("Send = %v, want validation", err)
				}
				if _, err := pat.History(ctx, ab2bus.HistoryInput{Channel: name}); ab2bus.CodeOf(err) != want {
					t.Errorf("History = %v, want %s", err, want)
				}
				if _, err := pat.CreateChannel(ctx, ab2bus.CreateChannelInput{Name: name}); ab2bus.CodeOf(err) != ab2bus.CodeValidation {
					t.Errorf("CreateChannel = %v, want validation", err)
				}
			})
		}
	})
}
