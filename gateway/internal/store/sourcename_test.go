package store

import (
	"context"
	"testing"

	trafficv1 "github.com/nklyshko/traffic-deck/gateway/gen/traffic/v1"
)

// The sessions.source_kind column used to hold a SourceKind enum name and now holds the
// producing tool's name. Old values keep arriving — from a catalog an older build wrote,
// and from a bundle an older build exported and someone imports today — so they are
// translated on read.
func TestSourceNameTranslatesLegacyEnumNames(t *testing.T) {
	for stored, want := range map[string]string{
		"SOURCE_KIND_CHROME":           "chrome",
		"SOURCE_KIND_MITMPROXY":        "mitmproxy",
		"SOURCE_KIND_ANDROID_EMULATOR": "android",
		"SOURCE_KIND_ANDROID_DEVICE":   "android",
		"SOURCE_KIND_GENERIC":          "import",
		"SOURCE_KIND_UNSPECIFIED":      "",
		// A kind this build never knew (written by a newer one, or since removed) is
		// blanked rather than shown raw — a viewer must never render "SOURCE_KIND_FOO".
		"SOURCE_KIND_SOMETHING_NEW": "",
		// Names pass through untouched, including a module's own.
		"chrome":      "chrome",
		"firefox":     "firefox",
		"acme-module": "acme-module",
		"":            "",
	} {
		if got := sourceName(stored); got != want {
			t.Errorf("sourceName(%q) = %q, want %q", stored, got, want)
		}
	}
}

// End to end over the real catalog: a row written by an older build reads back as a name.
func TestLegacySessionRowReadsBackAsSourceName(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	// Exactly what an older build's CreateSession wrote: the enum's String().
	if err := st.ImportSessionRow(ctx, &SessionRow{
		ID: "old", Label: "legacy", Source: "SOURCE_KIND_CHROME",
		Status: trafficv1.SessionStatus_SESSION_STATUS_CLOSED.String(), CreatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	sess, err := st.GetSession(ctx, "old")
	if err != nil {
		t.Fatal(err)
	}
	if sess.GetSource() != "chrome" {
		t.Errorf("legacy session source = %q, want chrome", sess.GetSource())
	}
}

// A session this build writes round-trips through export and back unchanged — the
// manifest keeps the old `source_kind` JSON key, so the two directions stay compatible.
func TestSourceRoundTripsThroughExportImport(t *testing.T) {
	ctx := context.Background()
	st, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	if err := st.CreateSession(ctx, NewSession{
		ID: "s1", Label: "l", Source: "firefox",
		Status: trafficv1.SessionStatus_SESSION_STATUS_OPEN,
	}); err != nil {
		t.Fatal(err)
	}
	row, err := st.ExportSessionRow(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if row.Source != "firefox" {
		t.Fatalf("exported source = %q, want firefox", row.Source)
	}
	row.ID = "s2"
	if err := st.ImportSessionRow(ctx, row); err != nil {
		t.Fatal(err)
	}
	sess, err := st.GetSession(ctx, "s2")
	if err != nil {
		t.Fatal(err)
	}
	if sess.GetSource() != "firefox" {
		t.Errorf("reimported source = %q, want firefox", sess.GetSource())
	}
}
