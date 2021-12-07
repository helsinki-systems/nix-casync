package store

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/numtide/go-nix/hash"
	"github.com/numtide/go-nix/nar/narinfo"
	"github.com/numtide/go-nix/nixbase32"
	"github.com/stretchr/testify/assert"
)

var (
	exampleNarinfo = &narinfo.NarInfo{
		StorePath:   "/nix/store/dr76fsw7d6ws3pymafx0w0sn4rzbw7c9-etc-os-release",
		URL:         "nar/1qv1l5zhzgqc66l0vjy2aw7z50fhga16anlyn2c1yp975aafmz93.nar.xz",
		Compression: "xz",
		FileHash:    hash.MustParseNixBase32("sha256:1qv1l5zhzgqc66l0vjy2aw7z50fhga16anlyn2c1yp975aafmz93"),
		FileSize:    332,
		NarHash:     hash.MustParseNixBase32("sha256:0mw6qwsrz35cck0wnjgmfnjzwnjbspsyihnfkng38kxghdc9k9zd"),
		NarSize:     464,
		References:  []string{},
		Deriver:     "hip5s2x9g0mqvamqhgkjxfhjw9mlm8j9-etc-os-release.drv",
		Signatures: []*narinfo.Signature{
			narinfo.MustParseSignatureLine("cache.nixos.org-1:SGA32M9KngPy2LK56n1QT0X1QwWRoBsXen74Z+K/WZKIPhMxb2PYbTO3N9A6uTzdJeT/wqJBILJmmRmeB/ygCw=="),
		},
	}
)

func TestNarInfo(t *testing.T) {
	bcs := NewMemoryStore()
	ctx := context.Background()

	hash := nixbase32.MustDecodeString("dr76fsw7d6ws3pymafx0w0sn4rzbw7c9")

	// Put a narinfo file
	err := bcs.PutNarInfo(ctx, hash, exampleNarinfo)
	if assert.NoError(t, err) {
		// Retrieve it back
		narinfo, err := bcs.GetNarInfo(ctx, hash)
		if assert.NoError(t, err) {
			assert.Equal(t, exampleNarinfo, narinfo)
		}
	}
}

func TestNar(t *testing.T) {
	bcs := NewMemoryStore()
	ctx := context.Background()

	narhash := nixbase32.MustDecodeString("0mw6qwsrz35cck0wnjgmfnjzwnjbspsyihnfkng38kxghdc9k9zd")

	// Put a .nar file
	w, err := bcs.PutNar(ctx, narhash)
	assert.NoError(t, err)

	data, err := os.ReadFile("../testdata/compression_none/nar/0mw6qwsrz35cck0wnjgmfnjzwnjbspsyihnfkng38kxghdc9k9zd.nar")
	if assert.NoError(t, err) {
		_, err := w.Write(data)
		if assert.NoError(t, err) {
			w.Close()

			// Get it back
			r, err := bcs.GetNar(ctx, narhash)
			if assert.NoError(t, err) {
				buf, err := io.ReadAll(r)
				if assert.NoError(t, err) {
					assert.Equal(t, data, buf)
				}
			}
		}
	}
}