package simg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tinyrange/gosimg/internal/image"
	"github.com/tinyrange/gosimg/internal/squashfs"
)

func TestWriteFromFetchDir(t *testing.T) {
	fetchDir := t.TempDir()
	layersDir := filepath.Join(fetchDir, "layers")
	if err := os.MkdirAll(layersDir, 0o755); err != nil {
		t.Fatalf("mkdir layers: %v", err)
	}

	layer1 := filepath.Join(layersDir, "01.tar.gz")
	if err := writeLayerTarGz(layer1, []tarEntry{
		{name: "etc", typ: tar.TypeDir, mode: 0o755, mtime: time.Unix(100, 0)},
		{name: "a.txt", typ: tar.TypeReg, mode: 0o644, data: []byte("one\n"), mtime: time.Unix(100, 0)},
		{name: "old.txt", typ: tar.TypeReg, mode: 0o644, data: []byte("old\n"), mtime: time.Unix(100, 0)},
	}); err != nil {
		t.Fatalf("write layer1: %v", err)
	}

	layer2 := filepath.Join(layersDir, "02.tar.gz")
	if err := writeLayerTarGz(layer2, []tarEntry{
		{name: ".wh.old.txt", typ: tar.TypeReg, mode: 0o644, data: nil, mtime: time.Unix(200, 0)},
		{name: "a.txt", typ: tar.TypeReg, mode: 0o644, data: []byte("two\n"), mtime: time.Unix(200, 0)},
		{name: "sub", typ: tar.TypeDir, mode: 0o755, mtime: time.Unix(200, 0)},
		{name: "sub/b.txt", typ: tar.TypeReg, mode: 0o644, data: []byte("b\n"), mtime: time.Unix(200, 0)},
	}); err != nil {
		t.Fatalf("write layer2: %v", err)
	}

	result := fetchResult{
		ImageRef:     "example:latest",
		Architecture: "amd64",
		OutputDir:    fetchDir,
		Layers: []fetchLayer{
			{Digest: "sha256:l1", MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip", Path: layer1},
			{Digest: "sha256:l2", MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip", Path: layer2},
		},
	}
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal fetch-result: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fetchDir, "fetch-result.json"), b, 0o644); err != nil {
		t.Fatalf("write fetch-result.json: %v", err)
	}

	out := filepath.Join(t.TempDir(), "fetch.simg")
	if err := WriteFromFetchDir(fetchDir, out, "amd64"); err != nil {
		t.Fatalf("WriteFromFetchDir: %v", err)
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

	_, inode, _, err := sq.ResolvePath("/a.txt")
	if err != nil {
		t.Fatalf("ResolvePath /a.txt: %v", err)
	}
	f, ok := inode.(*squashfs.FileInode)
	if !ok {
		t.Fatalf("/a.txt not file inode: %T", inode)
	}
	var got bytes.Buffer
	if err := sq.StreamFile(f, &got); err != nil {
		t.Fatalf("StreamFile /a.txt: %v", err)
	}
	if got.String() != "two\n" {
		t.Fatalf("unexpected /a.txt content: %q", got.String())
	}

	if _, _, _, err := sq.ResolvePath("/old.txt"); err == nil {
		t.Fatalf("expected /old.txt to be removed by whiteout")
	}
	if _, _, _, err := sq.ResolvePath("/sub/b.txt"); err != nil {
		t.Fatalf("ResolvePath /sub/b.txt: %v", err)
	}
}

type tarEntry struct {
	name  string
	typ   byte
	mode  int64
	data  []byte
	link  string
	mtime time.Time
}

func writeLayerTarGz(out string, entries []tarEntry) error {
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typ,
			Mode:     e.mode,
			ModTime:  e.mtime,
			Linkname: e.link,
		}
		if e.typ == tar.TypeReg || e.typ == tar.TypeRegA {
			hdr.Size = int64(len(e.data))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			tw.Close()
			gw.Close()
			return err
		}
		if e.typ == tar.TypeReg || e.typ == tar.TypeRegA {
			if _, err := tw.Write(e.data); err != nil {
				tw.Close()
				gw.Close()
				return err
			}
		}
	}

	if err := tw.Close(); err != nil {
		gw.Close()
		return err
	}
	if err := gw.Close(); err != nil {
		return err
	}
	return f.Close()
}
