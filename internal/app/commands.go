package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/tinyrange/gosimg/internal/image"
	"github.com/tinyrange/gosimg/internal/squashfs"
)

func RunMeta(imagePath string) error {
	img, err := image.Open(imagePath)
	if err != nil {
		return err
	}
	defer img.Close()

	sq, err := squashfs.Open(img)
	if err != nil {
		return err
	}

	fmt.Printf("image: %s\n", imagePath)
	fmt.Printf("size: %d bytes\n", img.Size)
	if img.SIF != nil {
		printSIFMeta(*img.SIF, img.Descriptors)
	}
	fmt.Printf("squashfs_offset: %d\n", img.SquashFSOffset)
	printSquashMeta(sq.Superblock())
	if len(img.Descriptors) > 0 {
		for _, d := range img.Descriptors {
			if isSquashFSPayload(img, d) {
				continue
			}
			if d.Size == 0 || d.Size > 1<<20 {
				continue
			}
			payload, err := image.ReadAtMost(img.F, int64(d.Offset), int(d.Size))
			if err != nil {
				return err
			}
			if !isLikelyText(payload) {
				continue
			}
			name := d.Name
			if name == "" {
				name = fmt.Sprintf("descriptor-%d", d.Index)
			}
			fmt.Printf("metadata_payload[%s]:\n", name)
			fmt.Printf("%s\n", strings.TrimRight(string(payload), "\n"))
		}
	}

	return nil
}

func RunList(imagePath, target string, recursive bool) error {
	img, err := image.Open(imagePath)
	if err != nil {
		return err
	}
	defer img.Close()

	sq, err := squashfs.Open(img)
	if err != nil {
		return err
	}

	ref, inode, cleanTarget, err := sq.ResolvePath(target)
	if err != nil {
		return err
	}

	switch n := inode.(type) {
	case *squashfs.DirInode:
		if recursive {
			return sq.ListRecursive(cleanTarget, ref, n, os.Stdout)
		}
		entries, err := sq.ReadDirectoryEntries(n)
		if err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
		for _, e := range entries {
			child, err := sq.ReadInode(e.InodeRef)
			if err != nil {
				return err
			}
			fmt.Printf("%s\t%s\n", squashfs.InodeKind(child), e.Name)
		}
		return nil
	default:
		fmt.Printf("%s\t%s\n", squashfs.InodeKind(n), cleanTarget)
		return nil
	}
}

func RunExtract(imagePath, target, out string) error {
	img, err := image.Open(imagePath)
	if err != nil {
		return err
	}
	defer img.Close()

	sq, err := squashfs.Open(img)
	if err != nil {
		return err
	}

	_, inode, cleanTarget, err := sq.ResolvePath(target)
	if err != nil {
		return err
	}

	fn, ok := inode.(*squashfs.FileInode)
	if !ok {
		return fmt.Errorf("%s is not a regular file", cleanTarget)
	}

	if out == "" {
		out = path.Base(cleanTarget)
		if out == "/" || out == "." || out == "" {
			return errors.New("cannot infer output filename for root path")
		}
	}

	var w io.Writer
	var closer io.Closer
	if out == "-" {
		w = os.Stdout
	} else {
		fileMode := os.FileMode(fn.Base.Mode & 0o777)
		if fileMode == 0 {
			fileMode = 0o644
		}
		f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fileMode)
		if err != nil {
			return err
		}
		w = f
		closer = f
	}
	if closer != nil {
		defer closer.Close()
	}

	return sq.StreamFile(fn, w)
}

func printSIFMeta(h image.SIFHeader, desc []image.SIFDescriptor) {
	fmt.Printf("sif_magic: %s\n", h.Magic)
	fmt.Printf("sif_version: %s.%s\n", h.VersionMajor, h.VersionMinor)
	fmt.Printf("sif_launch_script: %q\n", h.LaunchScript)
	fmt.Printf("sif_created_at: %s\n", time.Unix(h.CreatedAt, 0).UTC().Format(time.RFC3339))
	fmt.Printf("sif_modified_at: %s\n", time.Unix(h.ModifiedAt, 0).UTC().Format(time.RFC3339))
	fmt.Printf("sif_descriptors_total: %d\n", h.DescriptorsTotal)
	fmt.Printf("sif_descriptors_free: %d\n", h.DescriptorsFree)
	fmt.Printf("sif_descriptors_offset: %d\n", h.DescriptorsOffset)
	fmt.Printf("sif_data_offset: %d\n", h.DataOffset)
	fmt.Printf("sif_data_size: %d\n", h.DataSize)

	if len(desc) == 0 {
		fmt.Printf("sif_descriptors_used: 0\n")
		return
	}

	fmt.Printf("sif_descriptors_used: %d\n", len(desc))
	for _, d := range desc {
		name := d.Name
		if name == "" {
			name = "<unnamed>"
		}
		fmt.Printf("  - idx=%d type_raw=0x%x off=%d size=%d pad=%d name=%q\n", d.Index, d.DataTypeRaw, d.Offset, d.Size, d.SizeWithPadding, name)
	}
}

func printSquashMeta(sb squashfs.Superblock) {
	fmt.Printf("squashfs_magic: %s\n", string(sb.Magic[:]))
	fmt.Printf("squashfs_version: %d.%d\n", sb.Major, sb.Minor)
	fmt.Printf("squashfs_inodes: %d\n", sb.Inodes)
	fmt.Printf("squashfs_block_size: %d\n", sb.BlockSize)
	fmt.Printf("squashfs_compression: %d\n", sb.Compression)
	fmt.Printf("squashfs_fragments: %d\n", sb.Fragments)
	fmt.Printf("squashfs_bytes_used: %d\n", sb.BytesUsed)
	fmt.Printf("squashfs_mkfs_time: %s\n", time.Unix(int64(sb.MkfsTime), 0).UTC().Format(time.RFC3339))
}

func isSquashFSPayload(img *image.File, d image.SIFDescriptor) bool {
	magic, err := image.ReadAtMost(img.F, int64(d.Offset), len(image.SquashFSMagic))
	if err != nil {
		return false
	}
	return string(magic) == image.SquashFSMagic
}

func isLikelyText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 32 && c <= 126) {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) >= 0.95
}
