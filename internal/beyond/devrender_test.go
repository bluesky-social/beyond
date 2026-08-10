package beyond

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestDevRenderMintPages is a throwaway helper (gated on BEYOND_RENDER_DIR):
// it renders the three mint page states with sample data so they can be viewed
// in a browser. Not a real test — skipped unless the env var is set.
func TestDevRenderMintPages(t *testing.T) {
	dir := os.Getenv("BEYOND_RENDER_DIR")
	if dir == "" {
		t.Skip("set BEYOND_RENDER_DIR to render mint pages")
	}
	write := func(name string, tmplExec func(*bytes.Buffer) error) {
		var buf bytes.Buffer
		if err := tmplExec(&buf); err != nil {
			t.Fatalf("render %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	write("1-confirm.html", func(b *bytes.Buffer) error {
		return mintIndexTmpl.Execute(b, mintIndexData{CSRFToken: "sample-csrf-token", Nonce: "n1"})
	})
	write("2-result.html", func(b *bytes.Buffer) error {
		return mintResultTmpl.Execute(b, mintResultData{
			Composite: "test@beyond.local:aXmpleKeYvALue1234567890abcdefGHIJKLMNOPqrst",
			Username:  "test@beyond.local",
			Nonce:     "n2",
			ExpiresIn: "365 days",
		})
	})
	write("3-replay.html", func(b *bytes.Buffer) error {
		return mintNoticeTmpl.Execute(b, mintNoticeData{
			Title:   "Key already displayed",
			Message: "This link has already been used, or your session expired. Your key (if one was created) was shown only once. Start again to mint a new key.",
			Nonce:   "n3",
		})
	})
	write("4-orphan.html", func(b *bytes.Buffer) error {
		return mintNoticeTmpl.Execute(b, mintNoticeData{
			Title:     "Could not create key",
			Message:   "A key may have been created but could not be retrieved, and automatic cleanup failed. Please revoke your most recent app password in Authentik to be safe.",
			Nonce:     "n4",
			RevokeURL: "http://localhost:9000/if/user/#/settings;page-tokens",
		})
	})
	t.Logf("rendered mint pages to %s", dir)
}
