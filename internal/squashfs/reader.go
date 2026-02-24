package squashfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	img "github.com/tinyrange/gosimg/internal/image"
)

const (
	compZlib          = 1
	metaUncompressed  = 0x8000
	dataUncompressed  = 0x01000000
	dataSizeMask      = 0x00ffffff
	fragmentEntrySize = 16
	fragmentPerMeta   = 8192 / fragmentEntrySize

	inodeTypeBasicDir  = 1
	inodeTypeBasicFile = 2
	inodeTypeBasicSym  = 3
	inodeTypeLDir      = 8
	inodeTypeLFile     = 9
	inodeTypeLSym      = 10
)

type Superblock struct {
	Magic             [4]byte
	Inodes            uint32
	MkfsTime          uint32
	BlockSize         uint32
	Fragments         uint32
	Compression       uint16
	BlockLog          uint16
	Flags             uint16
	NoIDs             uint16
	Major             uint16
	Minor             uint16
	RootInode         uint64
	BytesUsed         uint64
	IDTableStart      uint64
	XattrIDTableStart uint64
	InodeTableStart   uint64
	DirectoryTable    uint64
	FragmentTable     uint64
	LookupTable       uint64
}

type Reader struct {
	f            *os.File
	base         int64
	sb           Superblock
	inodeMeta    *metaReader
	dirMeta      *metaReader
	fragmentPtrs []uint64
	fragCache    map[uint32][]byte
}

type metaReader struct {
	file  *os.File
	base  int64
	cache map[uint32]metaBlock
}

type metaBlock struct {
	data []byte
	next uint32
}

type metaCursor struct {
	r   *metaReader
	blk uint32
	off int
}

type DirEntry struct {
	Name      string
	InodeRef  uint64
	InodeType uint16
}

type InodeBase struct {
	InodeType uint16
	Mode      uint16
	UID       uint16
	GID       uint16
	MTime     uint32
	InodeNum  uint32
}

type DirInode struct {
	Base       InodeBase
	StartBlock uint32
	Offset     uint16
	SizeBytes  int
}

type FileInode struct {
	Base          InodeBase
	StartBlock    uint64
	FragmentIndex uint32
	FragmentOff   uint32
	FileSize      uint64
	BlockSizes    []uint32
}

type SymlinkInode struct {
	Base   InodeBase
	Target string
}

type UnknownInode struct {
	Base InodeBase
}

func Open(image *img.File) (*Reader, error) {
	base := image.SquashFSOffset
	if base < 0 {
		return nil, errors.New("invalid squashfs offset")
	}
	var sb Superblock
	if _, err := image.F.Seek(base, io.SeekStart); err != nil {
		return nil, err
	}
	if err := binary.Read(image.F, binary.LittleEndian, &sb); err != nil {
		return nil, err
	}
	if string(sb.Magic[:]) != img.SquashFSMagic {
		return nil, fmt.Errorf("invalid squashfs magic at %d", base)
	}
	if sb.Compression != compZlib {
		return nil, fmt.Errorf("unsupported squashfs compression %d (only zlib is supported)", sb.Compression)
	}

	sq := &Reader{
		f:    image.F,
		base: base,
		sb:   sb,
		inodeMeta: &metaReader{
			file:  image.F,
			base:  base + int64(sb.InodeTableStart),
			cache: map[uint32]metaBlock{},
		},
		dirMeta: &metaReader{
			file:  image.F,
			base:  base + int64(sb.DirectoryTable),
			cache: map[uint32]metaBlock{},
		},
		fragCache: map[uint32][]byte{},
	}

	if sb.Fragments > 0 {
		ptrCount := int((sb.Fragments + fragmentPerMeta - 1) / fragmentPerMeta)
		ptrBytes, err := img.ReadAtMost(image.F, base+int64(sb.FragmentTable), ptrCount*8)
		if err != nil {
			return nil, err
		}
		sq.fragmentPtrs = make([]uint64, 0, ptrCount)
		for i := 0; i < ptrCount; i++ {
			sq.fragmentPtrs = append(sq.fragmentPtrs, binary.LittleEndian.Uint64(ptrBytes[i*8:(i+1)*8]))
		}
	}

	return sq, nil
}

func (sq *Reader) Superblock() Superblock {
	return sq.sb
}

func (m *metaReader) readBlock(rel uint32) ([]byte, uint32, error) {
	if blk, ok := m.cache[rel]; ok {
		return blk.data, blk.next, nil
	}
	pos := m.base + int64(rel)
	if _, err := m.file.Seek(pos, io.SeekStart); err != nil {
		return nil, 0, err
	}
	var hdr uint16
	if err := binary.Read(m.file, binary.LittleEndian, &hdr); err != nil {
		return nil, 0, err
	}
	rawLen := int(hdr & 0x7fff)
	raw := make([]byte, rawLen)
	if _, err := io.ReadFull(m.file, raw); err != nil {
		return nil, 0, err
	}
	out := raw
	if hdr&metaUncompressed == 0 {
		zr, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, 0, err
		}
		decomp, err := io.ReadAll(zr)
		zr.Close()
		if err != nil {
			return nil, 0, err
		}
		out = decomp
	}
	next := rel + 2 + uint32(rawLen)
	m.cache[rel] = metaBlock{data: out, next: next}
	return out, next, nil
}

func (m *metaReader) readAt(block uint32, offset int, n int) ([]byte, error) {
	c := &metaCursor{r: m, blk: block, off: offset}
	return c.readN(n)
}

func (c *metaCursor) readN(n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("negative read")
	}
	out := make([]byte, 0, n)
	for len(out) < n {
		blk, next, err := c.r.readBlock(c.blk)
		if err != nil {
			return nil, err
		}
		if c.off >= len(blk) {
			c.blk = next
			c.off = 0
			continue
		}
		take := n - len(out)
		if left := len(blk) - c.off; left < take {
			take = left
		}
		out = append(out, blk[c.off:c.off+take]...)
		c.off += take
		if c.off >= len(blk) {
			c.blk = next
			c.off = 0
		}
	}
	return out, nil
}

func (sq *Reader) ResolvePath(p string) (uint64, any, string, error) {
	clean := CleanPath(p)
	ref := sq.sb.RootInode
	if clean == "/" {
		n, err := sq.ReadInode(ref)
		return ref, n, clean, err
	}

	n, err := sq.ReadInode(ref)
	if err != nil {
		return 0, nil, clean, err
	}
	parts := strings.Split(strings.TrimPrefix(clean, "/"), "/")
	for _, part := range parts {
		d, ok := n.(*DirInode)
		if !ok {
			return 0, nil, clean, fmt.Errorf("%q is not a directory while resolving %q", part, clean)
		}
		entries, err := sq.ReadDirectoryEntries(d)
		if err != nil {
			return 0, nil, clean, err
		}
		found := false
		for _, e := range entries {
			if e.Name == part {
				ref = e.InodeRef
				n, err = sq.ReadInode(ref)
				if err != nil {
					return 0, nil, clean, err
				}
				found = true
				break
			}
		}
		if !found {
			return 0, nil, clean, fmt.Errorf("path not found: %s", clean)
		}
	}
	return ref, n, clean, nil
}

func (sq *Reader) ReadInode(ref uint64) (any, error) {
	blk := uint32((ref >> 16) & 0xffffffff)
	off := int(uint16(ref & 0xffff))
	baseBytes, err := sq.inodeMeta.readAt(blk, off, 16)
	if err != nil {
		return nil, err
	}
	b := InodeBase{
		InodeType: binary.LittleEndian.Uint16(baseBytes[0:2]),
		Mode:      binary.LittleEndian.Uint16(baseBytes[2:4]),
		UID:       binary.LittleEndian.Uint16(baseBytes[4:6]),
		GID:       binary.LittleEndian.Uint16(baseBytes[6:8]),
		MTime:     binary.LittleEndian.Uint32(baseBytes[8:12]),
		InodeNum:  binary.LittleEndian.Uint32(baseBytes[12:16]),
	}

	switch b.InodeType {
	case inodeTypeBasicDir:
		raw, err := sq.inodeMeta.readAt(blk, off, 32)
		if err != nil {
			return nil, err
		}
		sz := int(binary.LittleEndian.Uint16(raw[24:26])) - 3
		if sz < 0 {
			sz = 0
		}
		return &DirInode{
			Base:       b,
			StartBlock: binary.LittleEndian.Uint32(raw[16:20]),
			Offset:     binary.LittleEndian.Uint16(raw[26:28]),
			SizeBytes:  sz,
		}, nil
	case inodeTypeLDir:
		raw, err := sq.inodeMeta.readAt(blk, off, 40)
		if err != nil {
			return nil, err
		}
		sz := int(binary.LittleEndian.Uint32(raw[20:24])) - 3
		if sz < 0 {
			sz = 0
		}
		return &DirInode{
			Base:       b,
			StartBlock: binary.LittleEndian.Uint32(raw[24:28]),
			Offset:     binary.LittleEndian.Uint16(raw[34:36]),
			SizeBytes:  sz,
		}, nil
	case inodeTypeBasicFile:
		raw32, err := sq.inodeMeta.readAt(blk, off, 32)
		if err != nil {
			return nil, err
		}
		fileSize := uint64(binary.LittleEndian.Uint32(raw32[28:32]))
		nBlocks := sq.fileBlockCount(fileSize, binary.LittleEndian.Uint32(raw32[20:24]))
		raw, err := sq.inodeMeta.readAt(blk, off, 32+nBlocks*4)
		if err != nil {
			return nil, err
		}
		blocks := make([]uint32, nBlocks)
		for i := 0; i < nBlocks; i++ {
			blocks[i] = binary.LittleEndian.Uint32(raw[32+i*4 : 36+i*4])
		}
		return &FileInode{
			Base:          b,
			StartBlock:    uint64(binary.LittleEndian.Uint32(raw32[16:20])),
			FragmentIndex: binary.LittleEndian.Uint32(raw32[20:24]),
			FragmentOff:   binary.LittleEndian.Uint32(raw32[24:28]),
			FileSize:      fileSize,
			BlockSizes:    blocks,
		}, nil
	case inodeTypeLFile:
		raw56, err := sq.inodeMeta.readAt(blk, off, 56)
		if err != nil {
			return nil, err
		}
		fileSize := binary.LittleEndian.Uint64(raw56[24:32])
		nBlocks := sq.fileBlockCount(fileSize, binary.LittleEndian.Uint32(raw56[44:48]))
		raw, err := sq.inodeMeta.readAt(blk, off, 56+nBlocks*4)
		if err != nil {
			return nil, err
		}
		blocks := make([]uint32, nBlocks)
		for i := 0; i < nBlocks; i++ {
			blocks[i] = binary.LittleEndian.Uint32(raw[56+i*4 : 60+i*4])
		}
		return &FileInode{
			Base:          b,
			StartBlock:    binary.LittleEndian.Uint64(raw56[16:24]),
			FragmentIndex: binary.LittleEndian.Uint32(raw56[44:48]),
			FragmentOff:   binary.LittleEndian.Uint32(raw56[48:52]),
			FileSize:      fileSize,
			BlockSizes:    blocks,
		}, nil
	case inodeTypeBasicSym:
		raw24, err := sq.inodeMeta.readAt(blk, off, 24)
		if err != nil {
			return nil, err
		}
		targetLen := int(binary.LittleEndian.Uint32(raw24[20:24]))
		raw, err := sq.inodeMeta.readAt(blk, off, 24+targetLen)
		if err != nil {
			return nil, err
		}
		return &SymlinkInode{Base: b, Target: string(raw[24 : 24+targetLen])}, nil
	case inodeTypeLSym:
		raw28, err := sq.inodeMeta.readAt(blk, off, 28)
		if err != nil {
			return nil, err
		}
		targetLen := int(binary.LittleEndian.Uint32(raw28[20:24]))
		raw, err := sq.inodeMeta.readAt(blk, off, 28+targetLen)
		if err != nil {
			return nil, err
		}
		return &SymlinkInode{Base: b, Target: string(raw[28 : 28+targetLen])}, nil
	default:
		return &UnknownInode{Base: b}, nil
	}
}

func (sq *Reader) fileBlockCount(size uint64, fragmentIdx uint32) int {
	if sq.sb.BlockSize == 0 {
		return 0
	}
	block := uint64(sq.sb.BlockSize)
	if fragmentIdx == 0xffffffff {
		return int((size + block - 1) / block)
	}
	return int(size / block)
}

func (sq *Reader) ReadDirectoryEntries(d *DirInode) ([]DirEntry, error) {
	entries := make([]DirEntry, 0, 64)
	cursor := &metaCursor{r: sq.dirMeta, blk: d.StartBlock, off: int(d.Offset)}
	remaining := d.SizeBytes

	for remaining > 0 {
		hdr, err := cursor.readN(12)
		if err != nil {
			return nil, err
		}
		remaining -= 12
		count := int(binary.LittleEndian.Uint32(hdr[0:4])) + 1
		startBlock := binary.LittleEndian.Uint32(hdr[4:8])
		for i := 0; i < count; i++ {
			eb, err := cursor.readN(8)
			if err != nil {
				return nil, err
			}
			remaining -= 8
			inodeOff := binary.LittleEndian.Uint16(eb[0:2])
			entryType := binary.LittleEndian.Uint16(eb[4:6])
			nameLen := int(binary.LittleEndian.Uint16(eb[6:8])) + 1
			nameBytes, err := cursor.readN(nameLen)
			if err != nil {
				return nil, err
			}
			remaining -= nameLen
			name := string(nameBytes)
			if name == "." || name == ".." {
				continue
			}
			ref := (uint64(startBlock) << 16) | uint64(inodeOff)
			entries = append(entries, DirEntry{Name: name, InodeRef: ref, InodeType: entryType})
		}
	}

	return entries, nil
}

func (sq *Reader) ListRecursive(basePath string, _ uint64, node *DirInode, w io.Writer) error {
	entries, err := sq.ReadDirectoryEntries(node)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })

	for _, e := range entries {
		childPath := path.Join(basePath, e.Name)
		if !strings.HasPrefix(childPath, "/") {
			childPath = "/" + childPath
		}
		child, err := sq.ReadInode(e.InodeRef)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "%s\t%s\n", InodeKind(child), childPath)
		if d, ok := child.(*DirInode); ok {
			if err := sq.ListRecursive(childPath, e.InodeRef, d, w); err != nil {
				return err
			}
		}
	}
	return nil
}

func (sq *Reader) StreamFile(fi *FileInode, w io.Writer) error {
	remaining := fi.FileSize
	if remaining == 0 {
		return nil
	}
	dataPos := fi.StartBlock
	blockSize := uint64(sq.sb.BlockSize)

	for i, enc := range fi.BlockSizes {
		if remaining == 0 {
			break
		}
		want := blockSize
		if remaining < want {
			want = remaining
		}
		if enc == 0 {
			zero := make([]byte, want)
			if _, err := w.Write(zero); err != nil {
				return err
			}
			remaining -= want
			continue
		}
		compLen := uint64(enc & dataSizeMask)
		raw, err := img.ReadAtMost(sq.f, sq.base+int64(dataPos), int(compLen))
		if err != nil {
			return err
		}
		dataPos += compLen

		var block []byte
		if enc&dataUncompressed != 0 {
			block = raw
		} else {
			zr, err := zlib.NewReader(bytes.NewReader(raw))
			if err != nil {
				return fmt.Errorf("decode block %d: %w", i, err)
			}
			dec, err := io.ReadAll(zr)
			zr.Close()
			if err != nil {
				return err
			}
			block = dec
		}
		if uint64(len(block)) < want {
			return fmt.Errorf("short decompressed block %d", i)
		}
		if _, err := w.Write(block[:want]); err != nil {
			return err
		}
		remaining -= want
	}

	if remaining > 0 {
		if fi.FragmentIndex == 0xffffffff {
			return fmt.Errorf("missing data tail: %d bytes", remaining)
		}
		frag, err := sq.readFragment(fi.FragmentIndex)
		if err != nil {
			return err
		}
		start := int(fi.FragmentOff)
		end := start + int(remaining)
		if start < 0 || end > len(frag) {
			return fmt.Errorf("fragment range out of bounds (idx=%d off=%d len=%d)", fi.FragmentIndex, fi.FragmentOff, len(frag))
		}
		if _, err := w.Write(frag[start:end]); err != nil {
			return err
		}
	}
	return nil
}

func (sq *Reader) readFragment(index uint32) ([]byte, error) {
	if index >= sq.sb.Fragments {
		return nil, fmt.Errorf("fragment index out of range: %d", index)
	}
	if b, ok := sq.fragCache[index]; ok {
		return b, nil
	}
	ptrIdx := index / fragmentPerMeta
	entryIdx := index % fragmentPerMeta
	if int(ptrIdx) >= len(sq.fragmentPtrs) {
		return nil, fmt.Errorf("fragment pointer out of range: %d", ptrIdx)
	}
	fragMetaOff := sq.fragmentPtrs[ptrIdx]
	m := &metaReader{file: sq.f, base: sq.base + int64(fragMetaOff), cache: map[uint32]metaBlock{}}
	blk, _, err := m.readBlock(0)
	if err != nil {
		return nil, err
	}
	entryPos := int(entryIdx) * fragmentEntrySize
	if entryPos+fragmentEntrySize > len(blk) {
		return nil, fmt.Errorf("fragment entry %d missing", index)
	}
	entry := blk[entryPos : entryPos+fragmentEntrySize]
	start := binary.LittleEndian.Uint64(entry[0:8])
	sizeEnc := binary.LittleEndian.Uint32(entry[8:12])
	compLen := uint64(sizeEnc & dataSizeMask)
	raw, err := img.ReadAtMost(sq.f, sq.base+int64(start), int(compLen))
	if err != nil {
		return nil, err
	}
	out := raw
	if sizeEnc&dataUncompressed == 0 {
		zr, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		dec, err := io.ReadAll(zr)
		zr.Close()
		if err != nil {
			return nil, err
		}
		out = dec
	}
	sq.fragCache[index] = out
	return out, nil
}

func InodeKind(v any) string {
	switch v.(type) {
	case *DirInode:
		return "dir"
	case *FileInode:
		return "file"
	case *SymlinkInode:
		return "symlink"
	default:
		return "other"
	}
}

func CleanPath(p string) string {
	if p == "" {
		return "/"
	}
	cp := path.Clean("/" + strings.TrimPrefix(p, "/"))
	if cp == "" {
		return "/"
	}
	return cp
}
