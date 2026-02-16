package cli

import (
	"testing"

	"github.com/fsnotify/fsnotify"
)

func TestIsWriteEvent(t *testing.T) {
	tests := []struct {
		name string
		op   fsnotify.Op
		want bool
	}{
		{"write", fsnotify.Write, true},
		{"create", fsnotify.Create, false},
		{"remove", fsnotify.Remove, false},
		{"rename", fsnotify.Rename, false},
		{"chmod", fsnotify.Chmod, false},
		{"write+create", fsnotify.Write | fsnotify.Create, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := fsnotify.Event{Name: "test.yaml", Op: tt.op}
			if got := isWriteEvent(e); got != tt.want {
				t.Errorf("isWriteEvent(%v) = %v, want %v", tt.op, got, tt.want)
			}
		})
	}
}

func TestSamePath(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"/foo/bar", "/foo/bar", true},
		{"/foo/bar/", "/foo/bar", true},
		{"/foo//bar", "/foo/bar", true},
		{"/foo/bar", "/foo/baz", false},
		{" /foo/bar ", "/foo/bar", true},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			if got := samePath(tt.a, tt.b); got != tt.want {
				t.Errorf("samePath(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
