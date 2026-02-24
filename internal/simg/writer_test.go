package simg

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tinyrange/gosimg/internal/image"
	"github.com/tinyrange/gosimg/internal/squashfs"
)

func TestWriteFromDir(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hello simg\n"), 0o644); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "config.ini"), []byte("k=v\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.Symlink("hello.txt", filepath.Join(root, "hello.link")); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatalf("symlink: %v", err)
		}
	}

	out := filepath.Join(t.TempDir(), "test.simg")
	if err := WriteFromDir(root, out, "amd64"); err != nil {
		t.Fatalf("WriteFromDir: %v", err)
	}

	img, err := image.Open(out)
	if err != nil {
		t.Fatalf("image.Open: %v", err)
	}
	defer img.Close()

	sq, err := squashfs.Open(img)
	if err != nil {
		t.Fatalf("squashfs.Open: %v", err)
	}

	_, inode, _, err := sq.ResolvePath("/hello.txt")
	if err != nil {
		t.Fatalf("ResolvePath hello.txt: %v", err)
	}
	f, ok := inode.(*squashfs.FileInode)
	if !ok {
		t.Fatalf("hello.txt not a file inode: %T", inode)
	}
	var got bytes.Buffer
	if err := sq.StreamFile(f, &got); err != nil {
		t.Fatalf("StreamFile hello.txt: %v", err)
	}
	if got.String() != "hello simg\n" {
		t.Fatalf("hello.txt content mismatch: %q", got.String())
	}

	if _, _, _, err := sq.ResolvePath("/etc/config.ini"); err != nil {
		t.Fatalf("ResolvePath config.ini: %v", err)
	}

	if runtime.GOOS != "windows" {
		_, inode, _, err = sq.ResolvePath("/hello.link")
		if err != nil {
			t.Fatalf("ResolvePath hello.link: %v", err)
		}
		if _, ok := inode.(*squashfs.SymlinkInode); !ok {
			t.Fatalf("hello.link not a symlink inode: %T", inode)
		}
	}
}
