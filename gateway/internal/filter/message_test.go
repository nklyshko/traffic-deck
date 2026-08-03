package filter

import (
	"strings"
	"testing"
)

func testMessage() *Message {
	return &Message{
		Opcode: "text", FromClient: true,
		MarkColor: "red", Favorite: true,
		TagNames: []string{"t-auth"}, GroupNames: []string{"g-api"},
		Comments: []string{"looks suspicious"},
		Payload:  func() string { return `{"op":"subscribe","channel":"trades"}` },
	}
}

func matchMsg(t *testing.T, expr string) bool {
	t.Helper()
	p, err := CompileMessage(expr, names, groups)
	if err != nil {
		t.Fatalf("compile %q: %v", expr, err)
	}
	return p.Match(testMessage())
}

func TestMessageTermsMatchTheirField(t *testing.T) {
	for _, c := range []struct {
		expr string
		want bool
	}{
		{"~op text", true}, {"~op binary", false},
		{"~from client", true}, {"~from server", false},
		{"~from c", true}, {"~from s", false}, // "client" holds no 's'
		{"~b subscribe", true}, {"~b unsubscribe", false},
		{"~mark red", true}, {"~mark blue", false},
		{"~tag auth", true}, {"~tag other", false},
		{"~group api", true},
		{"~comment suspicious", true},
		{"~fav", true},
		{"trades", true},       // a bare regex matches the payload
		{"api.example", false}, // ...not a URL: a message has none
		{"!~op binary", true},
		{"~op text ~b trades", true},
		{"~op text ~b nothing", false},
	} {
		if got := matchMsg(t, c.expr); got != c.want {
			t.Errorf("%q: got %v, want %v", c.expr, got, c.want)
		}
	}
}

func TestEmptyMessageFilterMatchesEverything(t *testing.T) {
	p, err := CompileMessage("  ", names, groups)
	if err != nil {
		t.Fatal(err)
	}
	if p != nil {
		t.Fatalf("empty expression should compile to a nil predicate, got %#v", p)
	}
	if !p.Match(testMessage()) {
		t.Error("a nil predicate must match everything")
	}
}

// A flow term brought over to the message language is refused by name rather than falling
// through to a payload regex that quietly matches nothing.
func TestFlowTermsAreRefusedForMessages(t *testing.T) {
	for _, expr := range []string{"~m GET", "~c 200", "~h cookie", "~d example.com", "~bq x"} {
		_, err := CompileMessage(expr, names, groups)
		if err == nil {
			t.Fatalf("%q: expected an error naming the unknown term", expr)
		}
		term := strings.Fields(expr)[0]
		if !strings.Contains(err.Error(), term) {
			t.Errorf("%q: error should name %q, got %v", expr, term, err)
		}
	}
}

func TestMessageTermNeedingAnArgumentSaysSo(t *testing.T) {
	if _, err := CompileMessage("~op", names, groups); err == nil ||
		!strings.Contains(err.Error(), "needs an argument") {
		t.Fatalf("expected a missing-argument error, got %v", err)
	}
}

// A payload term is the only expensive one, so it sorts last: a frame rejected by its
// opcode must never cost a payload read.
func TestPayloadIsReadOnlyAfterCheaperTermsPass(t *testing.T) {
	p, err := CompileMessage("~b trades ~op binary", names, groups)
	if err != nil {
		t.Fatal(err)
	}
	m := testMessage()
	reads := 0
	m.Payload = func() string { reads++; return "trades" }
	if p.Match(m) {
		t.Fatal("~op binary should have rejected a text frame")
	}
	if reads != 0 {
		t.Errorf("payload read %d times for a frame rejected by its opcode", reads)
	}
	if !p.ReadsPayloads() {
		t.Error("ReadsPayloads should be true for an expression holding ~b")
	}
}

func TestReadsPayloadsIsFalseWithoutAPayloadTerm(t *testing.T) {
	p, err := CompileMessage("~op text ~from client", names, groups)
	if err != nil {
		t.Fatal(err)
	}
	if p.ReadsPayloads() {
		t.Error("no ~b and no bare regex: nothing should need the payload")
	}
	// A frame whose payload cannot be loaded still matches the cheap terms.
	m := testMessage()
	m.Payload = nil
	if !p.Match(m) {
		t.Error("a payload-less frame should still match opcode/direction terms")
	}
}

func TestMessageHintsWarnAboutStrayOperators(t *testing.T) {
	h := MessageHints("~op text & ~from client")
	if len(h) == 0 || !strings.Contains(h[0], "not an operator") {
		t.Fatalf("expected a stray-operator hint, got %v", h)
	}
	if !strings.Contains(h[0], "the payload") {
		t.Errorf("the hint should say where the stray token was matched, got %q", h[0])
	}
	// The status-code hint belongs to the flow language; a message filter has no ~c.
	if h := MessageHints("~op text 200"); len(h) != 0 {
		t.Errorf("a bare number is an ordinary payload regex for messages, got hints %v", h)
	}
}

// A decoder's own header fields are matched by ~meta, the same term a flow's source
// metadata uses — the language knows there are keys, not what any of them mean.
func TestMessageMetadataTerm(t *testing.T) {
	m := testMessage()
	m.Metadata = map[string]string{"max.cmd": "Response(1)", "max.seq": "17"}
	for _, c := range []struct {
		expr string
		want bool
	}{
		{"~meta max.cmd=Response", true},
		{"~meta max.cmd=Request", false},
		{`~meta max.cmd=\(1\)`, true},
		{"~meta max.seq=^17$", true},
		{"~meta max.cmd", true}, // presence, no `=`
		{"~meta max.absent", false},
		{"!~meta max.cmd=Request", true},
	} {
		p, err := CompileMessage(c.expr, names, groups)
		if err != nil {
			t.Fatalf("compile %q: %v", c.expr, err)
		}
		if got := p.Match(m); got != c.want {
			t.Errorf("%q: got %v, want %v", c.expr, got, c.want)
		}
	}
	// A metadata term is a column read, so it must not cost a payload fetch.
	p, _ := CompileMessage("~meta max.cmd=Response", names, groups)
	if p.ReadsPayloads() {
		t.Error("~meta should not need the payload")
	}
}
