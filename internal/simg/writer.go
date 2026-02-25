package simg

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	sifHeaderSize     = 4096
	sifDescriptorSize = 585

	sifDataPartition = int32(0x4004)
	sifGroupMask     = uint32(0xf0000000)

	squashMagic = "hsqs"

	squashCompressionZlib = 1
	squashVersionMajor    = 4
	squashVersionMinor    = 0

	squashMetaBlockSize = 8192
	squashBlockSize     = 1 << 20 // 1 MiB

	squashMetaUncompressed = 0x8000
	squashDataUncompressed = 0x01000000

	squashInodeBasicDir  = 1
	squashInodeBasicFile = 2
	squashInodeBasicSym  = 3
	squashInodeLongDir   = 8
	squashInodeLongFile  = 9

	squashNoFragments = 0

	squashNoXattrTable  = ^uint64(0)
	squashNoLookupTable = ^uint64(0)
	squashNoFragTable   = ^uint64(0)

	squashNoFragment = uint32(0xffffffff)
	squashNoXattr    = uint32(0xffffffff)
)

var errUnsupportedFileType = errors.New("unsupported file type")

type nodeKind uint8

const (
	nodeDirectory nodeKind = iota + 1
	nodeRegular
	nodeSymlink
)

type node struct {
	name    string
	absPath string
	kind    nodeKind
	mode    fs.FileMode
	mtime   uint32
	size    uint64
	link    string

	parent   *node
	children []*node

	inodeType uint16
	inodeSize int
	inodeNum  uint32
	inodeRef  uint64

	fileStartRel uint64
	fileBlocks   []uint32

	// For OCI-layer sourced regular files.
	sourceKey    string
	sourceLayer  int
	sourceSeq    int
	sourceOrigin bool

	dirLen       int
	dirStartRel  uint64
	dirStartBlk  uint32
	dirStartOff  uint16
	dirChildBase uint32
}

type sifHeader struct {
	LaunchScript      [32]byte
	Magic             [10]byte
	Version           [3]byte
	Arch              [3]byte
	UUID              [16]byte
	CreatedAt         int64
	ModifiedAt        int64
	DescriptorsFree   int64
	DescriptorsTotal  int64
	DescriptorsOffset int64
	DescriptorsSize   int64
	DataOffset        int64
	DataSize          int64
}

type sifDescriptor struct {
	DataType        int32
	Used            bool
	ID              uint32
	GroupID         uint32
	LinkedID        uint32
	Offset          int64
	Size            int64
	SizeWithPadding int64

	CreatedAt  int64
	ModifiedAt int64
	UID        int64
	GID        int64
	Name       [128]byte
	Extra      [384]byte
}

type sifPartitionExtra struct {
	FSType   int32
	PartType int32
	Arch     [3]byte
}

type squashSuperblock struct {
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

type writeState struct {
	f      *os.File
	base   int64
	relPos uint64
}

func WriteFromDir(srcDir, outPath, arch string) error {
	if strings.TrimSpace(srcDir) == "" {
		return errors.New("source directory is required")
	}
	if strings.TrimSpace(outPath) == "" {
		return errors.New("output path is required")
	}

	absSrc, err := filepath.Abs(srcDir)
	if err != nil {
		return fmt.Errorf("resolve source directory: %w", err)
	}

	st, err := os.Stat(absSrc)
	if err != nil {
		return fmt.Errorf("stat source directory: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("source path is not a directory: %s", absSrc)
	}

	normArch := normalizeArch(arch)

	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create output file %s: %w", outPath, err)
	}
	defer f.Close()

	dataOffset := int64(sifHeaderSize + sifDescriptorSize)
	squashOffset := alignUp(dataOffset, 4096)
	if _, err := f.Write(make([]byte, squashOffset)); err != nil {
		return fmt.Errorf("initialize output file: %w", err)
	}

	root, allNodes, err := buildTree(absSrc)
	if err != nil {
		return err
	}

	ws := &writeState{f: f, base: squashOffset, relPos: 0}
	if err := ws.seekRelative(0); err != nil {
		return err
	}

	squashSize, err := writeSquashFS(ws, root, allNodes, writeFileData)
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	hdr, desc, err := newSIFHeaderAndDescriptor(normArch, now, squashOffset, squashSize)
	if err != nil {
		return err
	}

	if err := writeSIFHeaderAndDescriptor(f, hdr, desc); err != nil {
		return err
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync output file: %w", err)
	}

	return nil
}

func buildTree(rootDir string) (*node, []*node, error) {
	rootInfo, err := os.Lstat(rootDir)
	if err != nil {
		return nil, nil, fmt.Errorf("lstat %s: %w", rootDir, err)
	}

	root := &node{
		name:    "",
		absPath: rootDir,
		kind:    nodeDirectory,
		mode:    rootInfo.Mode(),
		mtime:   toUnix32(rootInfo.ModTime()),
	}

	all := []*node{root}
	lookup := map[string]*node{rootDir: root}

	err = filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == rootDir {
			return nil
		}

		parentPath := filepath.Dir(path)
		parent := lookup[parentPath]
		if parent == nil {
			return fmt.Errorf("internal tree error: missing parent for %s", path)
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}

		n := &node{
			name:    filepath.Base(path),
			absPath: path,
			mode:    info.Mode(),
			mtime:   toUnix32(info.ModTime()),
			parent:  parent,
		}

		switch {
		case d.IsDir():
			n.kind = nodeDirectory
			lookup[path] = n
		case info.Mode().Type() == 0:
			n.kind = nodeRegular
			n.size = uint64(info.Size())
		case info.Mode()&os.ModeSymlink != 0:
			n.kind = nodeSymlink
			target, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("read symlink %s: %w", path, err)
			}
			n.link = target
		default:
			return fmt.Errorf("%w: %s (%s)", errUnsupportedFileType, path, info.Mode().Type().String())
		}

		parent.children = append(parent.children, n)
		all = append(all, n)
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("walk source directory: %w", err)
	}

	for _, n := range all {
		if len(n.children) == 0 {
			continue
		}
		sort.Slice(n.children, func(i, j int) bool { return n.children[i].name < n.children[j].name })
	}

	return root, all, nil
}

func writeSquashFS(ws *writeState, root *node, all []*node, writeFiles func(*writeState, []*node) error) (int64, error) {
	if err := reserveSquashSuperblock(ws); err != nil {
		return 0, err
	}

	inodes := inodeOrder(root)
	for i, n := range inodes {
		n.inodeNum = uint32(i + 1)
	}

	if err := writeFiles(ws, inodes); err != nil {
		return 0, err
	}

	return finalizeSquashFS(ws, root, all, inodes)
}

func writeSquashFSPrepared(ws *writeState, root *node, all []*node) (int64, error) {
	inodes := inodeOrder(root)
	for i, n := range inodes {
		n.inodeNum = uint32(i + 1)
	}

	return finalizeSquashFS(ws, root, all, inodes)
}

func reserveSquashSuperblock(ws *writeState) error {
	if err := ws.write(make([]byte, binary.Size(squashSuperblock{}))); err != nil {
		return fmt.Errorf("reserve squashfs superblock: %w", err)
	}
	return nil
}

func finalizeSquashFS(ws *writeState, root *node, all, inodes []*node) (int64, error) {

	assignInodeTypesAndSizes(inodes)
	assignInodeRefs(inodes)

	dirs := directoryOrder(inodes)
	assignDirectoryLayout(dirs)

	inodeTableStart := ws.relPos
	if err := writeInodeTable(ws, inodes); err != nil {
		return 0, err
	}

	dirTableStart := ws.relPos
	if err := writeDirectoryTable(ws, dirs); err != nil {
		return 0, err
	}

	idTableStart, err := writeIDTable(ws)
	if err != nil {
		return 0, err
	}

	bytesUsed := ws.relPos
	sb := squashSuperblock{
		Inodes:            uint32(len(all)),
		MkfsTime:          uint32(time.Now().Unix()),
		BlockSize:         squashBlockSize,
		Fragments:         squashNoFragments,
		Compression:       squashCompressionZlib,
		BlockLog:          blockLog2(squashBlockSize),
		Flags:             0,
		NoIDs:             1,
		Major:             squashVersionMajor,
		Minor:             squashVersionMinor,
		RootInode:         root.inodeRef,
		BytesUsed:         bytesUsed,
		IDTableStart:      idTableStart,
		XattrIDTableStart: squashNoXattrTable,
		InodeTableStart:   inodeTableStart,
		DirectoryTable:    dirTableStart,
		FragmentTable:     squashNoFragTable,
		LookupTable:       squashNoLookupTable,
	}
	copy(sb.Magic[:], []byte(squashMagic))

	if err := ws.writeAt(0, sb); err != nil {
		return 0, fmt.Errorf("write squashfs superblock: %w", err)
	}

	return int64(bytesUsed), nil
}

func writeFileData(ws *writeState, inodes []*node) error {
	buf := make([]byte, squashBlockSize)

	for _, n := range inodes {
		if n.kind != nodeRegular {
			continue
		}

		n.fileStartRel = ws.relPos
		n.fileBlocks = n.fileBlocks[:0]

		if n.size == 0 {
			continue
		}

		f, err := os.Open(n.absPath)
		if err != nil {
			return fmt.Errorf("open %s: %w", n.absPath, err)
		}

		for {
			nr, readErr := io.ReadFull(f, buf)
			if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
				f.Close()
				return fmt.Errorf("read %s: %w", n.absPath, readErr)
			}
			if nr > 0 {
				if err := ws.write(buf[:nr]); err != nil {
					f.Close()
					return fmt.Errorf("write file data for %s: %w", n.absPath, err)
				}
				n.fileBlocks = append(n.fileBlocks, uint32(nr)|squashDataUncompressed)
			}
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				break
			}
		}

		if err := f.Close(); err != nil {
			return fmt.Errorf("close %s: %w", n.absPath, err)
		}
	}

	return nil
}

func inodeOrder(root *node) []*node {
	var out []*node
	var walk func(n *node)
	walk = func(n *node) {
		out = append(out, n)
		for _, c := range n.children {
			walk(c)
		}
	}
	walk(root)
	return out
}

func directoryOrder(inodes []*node) []*node {
	dirs := make([]*node, 0)
	for _, n := range inodes {
		if n.kind == nodeDirectory {
			dirs = append(dirs, n)
		}
	}
	return dirs
}

func assignInodeTypesAndSizes(inodes []*node) {
	for _, n := range inodes {
		switch n.kind {
		case nodeDirectory:
			n.inodeType = squashInodeLongDir
			n.inodeSize = 40
		case nodeRegular:
			if n.size > 0xffffffff {
				n.inodeType = squashInodeLongFile
				n.inodeSize = 56 + len(n.fileBlocks)*4
			} else {
				n.inodeType = squashInodeBasicFile
				n.inodeSize = 32 + len(n.fileBlocks)*4
			}
		case nodeSymlink:
			n.inodeType = squashInodeBasicSym
			n.inodeSize = 24 + len(n.link)
		}
	}
}

func assignInodeRefs(inodes []*node) {
	var blockRel uint32
	var off uint16

	for _, n := range inodes {
		n.inodeRef = (uint64(blockRel) << 16) | uint64(off)
		advance := n.inodeSize

		for advance > 0 {
			left := squashMetaBlockSize - int(off)
			if advance < left {
				off += uint16(advance)
				advance = 0
				continue
			}
			advance -= left
			blockRel += uint32(2 + squashMetaBlockSize)
			off = 0
		}
	}
}

func assignDirectoryLayout(dirs []*node) {
	var logical uint64
	for _, d := range dirs {
		d.dirStartRel = logical
		d.dirLen, d.dirChildBase = estimateDirBytes(d)
		logical += uint64(d.dirLen)

		dirBlock := d.dirStartRel / squashMetaBlockSize
		d.dirStartBlk = uint32(dirBlock * (squashMetaBlockSize + 2))
		d.dirStartOff = uint16(d.dirStartRel % squashMetaBlockSize)
	}
}

func estimateDirBytes(d *node) (int, uint32) {
	if len(d.children) == 0 {
		return 0, 0
	}

	total := 0
	var currentStart uint32
	count := 0
	base := uint32(0)
	for i, c := range d.children {
		childStart := uint32(c.inodeRef >> 16)
		if i == 0 {
			currentStart = childStart
			base = c.inodeNum
			total += 12
			count = 0
		}
		if childStart != currentStart || count == 256 {
			currentStart = childStart
			total += 12
			count = 0
		}
		total += 8 + len(c.name)
		count++
	}
	return total, base
}

func writeInodeTable(ws *writeState, inodes []*node) error {
	mw := newMetaWriter(ws)
	for _, n := range inodes {
		rec, err := encodeInode(n)
		if err != nil {
			return err
		}
		if err := mw.write(rec); err != nil {
			return err
		}
	}
	return mw.close()
}

func writeDirectoryTable(ws *writeState, dirs []*node) error {
	mw := newMetaWriter(ws)
	for _, d := range dirs {
		if err := writeDirRecords(mw, d); err != nil {
			return err
		}
	}
	return mw.close()
}

func writeIDTable(ws *writeState) (uint64, error) {
	// SquashFS stores ID metadata blocks first, then an index of pointers.
	// The superblock's IDTableStart references the pointer table.
	metaPos := ws.relPos
	var hdr [2]byte
	binary.LittleEndian.PutUint16(hdr[:], squashMetaUncompressed|4)
	if err := ws.write(hdr[:]); err != nil {
		return 0, fmt.Errorf("write id table metadata header: %w", err)
	}

	var id [4]byte
	binary.LittleEndian.PutUint32(id[:], 0)
	if err := ws.write(id[:]); err != nil {
		return 0, fmt.Errorf("write id table metadata payload: %w", err)
	}

	pointerPos := ws.relPos
	var ptr [8]byte
	binary.LittleEndian.PutUint64(ptr[:], metaPos)
	if err := ws.write(ptr[:]); err != nil {
		return 0, fmt.Errorf("write id table pointer: %w", err)
	}

	return pointerPos, nil
}

func encodeInode(n *node) ([]byte, error) {
	mode, err := inodeMode(n)
	if err != nil {
		return nil, err
	}

	switch n.kind {
	case nodeDirectory:
		b := make([]byte, 40)
		putBaseInode(b, n.inodeType, mode, n.mtime, n.inodeNum)
		binary.LittleEndian.PutUint32(b[16:20], uint32(len(n.children)+2))
		binary.LittleEndian.PutUint32(b[20:24], uint32(n.dirLen+3))
		binary.LittleEndian.PutUint32(b[24:28], n.dirStartBlk)
		parent := n.inodeNum
		if n.parent != nil {
			parent = n.parent.inodeNum
		}
		binary.LittleEndian.PutUint32(b[28:32], parent)
		binary.LittleEndian.PutUint16(b[32:34], uint16(len(n.children)))
		binary.LittleEndian.PutUint16(b[34:36], n.dirStartOff)
		binary.LittleEndian.PutUint32(b[36:40], squashNoXattr)
		return b, nil

	case nodeRegular:
		if n.inodeType == squashInodeLongFile {
			b := make([]byte, 56+4*len(n.fileBlocks))
			putBaseInode(b, n.inodeType, mode, n.mtime, n.inodeNum)
			binary.LittleEndian.PutUint64(b[16:24], n.fileStartRel)
			binary.LittleEndian.PutUint64(b[24:32], n.size)
			binary.LittleEndian.PutUint64(b[32:40], 0)
			binary.LittleEndian.PutUint32(b[40:44], 1)
			binary.LittleEndian.PutUint32(b[44:48], squashNoFragment)
			binary.LittleEndian.PutUint32(b[48:52], 0)
			binary.LittleEndian.PutUint32(b[52:56], squashNoXattr)
			for i, enc := range n.fileBlocks {
				binary.LittleEndian.PutUint32(b[56+i*4:60+i*4], enc)
			}
			return b, nil
		}

		b := make([]byte, 32+4*len(n.fileBlocks))
		putBaseInode(b, n.inodeType, mode, n.mtime, n.inodeNum)
		binary.LittleEndian.PutUint32(b[16:20], uint32(n.fileStartRel))
		binary.LittleEndian.PutUint32(b[20:24], squashNoFragment)
		binary.LittleEndian.PutUint32(b[24:28], 0)
		binary.LittleEndian.PutUint32(b[28:32], uint32(n.size))
		for i, enc := range n.fileBlocks {
			binary.LittleEndian.PutUint32(b[32+i*4:36+i*4], enc)
		}
		return b, nil

	case nodeSymlink:
		b := make([]byte, 24+len(n.link))
		putBaseInode(b, n.inodeType, mode, n.mtime, n.inodeNum)
		binary.LittleEndian.PutUint32(b[16:20], 1)
		binary.LittleEndian.PutUint32(b[20:24], uint32(len(n.link)))
		copy(b[24:], []byte(n.link))
		return b, nil
	}

	return nil, fmt.Errorf("unknown inode kind for %s", n.absPath)
}

func writeDirRecords(mw *metaWriter, d *node) error {
	if len(d.children) == 0 {
		return nil
	}

	i := 0
	for i < len(d.children) {
		start := i
		startBlk := uint32(d.children[i].inodeRef >> 16)
		for i < len(d.children) && uint32(d.children[i].inodeRef>>16) == startBlk && (i-start) < 256 {
			i++
		}
		count := i - start

		hdr := make([]byte, 12)
		binary.LittleEndian.PutUint32(hdr[0:4], uint32(count-1))
		binary.LittleEndian.PutUint32(hdr[4:8], startBlk)
		binary.LittleEndian.PutUint32(hdr[8:12], d.children[start].inodeNum)
		if err := mw.write(hdr); err != nil {
			return err
		}

		for j := start; j < i; j++ {
			c := d.children[j]
			name := []byte(c.name)
			if len(name) == 0 || len(name) > 65536 {
				return fmt.Errorf("invalid entry name length %d in %s", len(name), c.absPath)
			}

			e := make([]byte, 8)
			binary.LittleEndian.PutUint16(e[0:2], uint16(c.inodeRef&0xffff))
			binary.LittleEndian.PutUint16(e[2:4], 0)
			binary.LittleEndian.PutUint16(e[4:6], dirEntryType(c))
			binary.LittleEndian.PutUint16(e[6:8], uint16(len(name)-1))
			if err := mw.write(e); err != nil {
				return err
			}
			if err := mw.write(name); err != nil {
				return err
			}
		}
	}

	return nil
}

func putBaseInode(b []byte, inodeType uint16, mode uint16, mtime uint32, inodeNum uint32) {
	binary.LittleEndian.PutUint16(b[0:2], inodeType)
	binary.LittleEndian.PutUint16(b[2:4], mode)
	binary.LittleEndian.PutUint16(b[4:6], 0)
	binary.LittleEndian.PutUint16(b[6:8], 0)
	binary.LittleEndian.PutUint32(b[8:12], mtime)
	binary.LittleEndian.PutUint32(b[12:16], inodeNum)
}

func inodeMode(n *node) (uint16, error) {
	perm := uint16(n.mode.Perm())
	switch n.kind {
	case nodeDirectory:
		return perm | 0x4000, nil
	case nodeRegular:
		return perm | 0x8000, nil
	case nodeSymlink:
		if perm == 0 {
			perm = 0o777
		}
		return perm | 0xa000, nil
	default:
		return 0, fmt.Errorf("unknown node kind for %s", n.absPath)
	}
}

func dirEntryType(n *node) uint16 {
	switch n.kind {
	case nodeDirectory:
		return squashInodeBasicDir
	case nodeRegular:
		return squashInodeBasicFile
	case nodeSymlink:
		return squashInodeBasicSym
	default:
		return 0
	}
}

type metaWriter struct {
	ws   *writeState
	buf  [squashMetaBlockSize]byte
	used int
}

func newMetaWriter(ws *writeState) *metaWriter {
	return &metaWriter{ws: ws}
}

func (mw *metaWriter) write(p []byte) error {
	for len(p) > 0 {
		left := len(mw.buf) - mw.used
		if left == 0 {
			if err := mw.flush(); err != nil {
				return err
			}
			left = len(mw.buf)
		}
		n := left
		if len(p) < n {
			n = len(p)
		}
		copy(mw.buf[mw.used:], p[:n])
		mw.used += n
		p = p[n:]
	}
	return nil
}

func (mw *metaWriter) close() error {
	if mw.used == 0 {
		return nil
	}
	return mw.flush()
}

func (mw *metaWriter) flush() error {
	if mw.used == 0 {
		return nil
	}

	var hdr [2]byte
	binary.LittleEndian.PutUint16(hdr[:], squashMetaUncompressed|uint16(mw.used))
	if err := mw.ws.write(hdr[:]); err != nil {
		return err
	}
	if err := mw.ws.write(mw.buf[:mw.used]); err != nil {
		return err
	}
	mw.used = 0
	return nil
}

func newSIFHeaderAndDescriptor(arch string, now int64, squashOffset int64, squashSize int64) (sifHeader, sifDescriptor, error) {
	if squashOffset < (sifHeaderSize + sifDescriptorSize) {
		return sifHeader{}, sifDescriptor{}, errors.New("invalid squashfs offset")
	}

	dataOffset := int64(sifHeaderSize + sifDescriptorSize)
	sizeWithPad := squashSize + (squashOffset - dataOffset)

	var h sifHeader
	copy(h.Magic[:], []byte("SIF_MAGIC\x00"))
	copy(h.Version[:], []byte{'0', '1', 0})
	h.Arch = sifArch(arch)
	if _, err := io.ReadFull(rand.Reader, h.UUID[:]); err != nil {
		return sifHeader{}, sifDescriptor{}, fmt.Errorf("generate UUID bytes: %w", err)
	}
	h.CreatedAt = now
	h.ModifiedAt = now
	h.DescriptorsFree = 0
	h.DescriptorsTotal = 1
	h.DescriptorsOffset = sifHeaderSize
	h.DescriptorsSize = sifDescriptorSize
	h.DataOffset = dataOffset
	h.DataSize = sizeWithPad

	var d sifDescriptor
	d.DataType = sifDataPartition
	d.Used = true
	d.ID = 1
	d.GroupID = sifGroupMask | 1
	d.LinkedID = 0
	d.Offset = squashOffset
	d.Size = squashSize
	d.SizeWithPadding = sizeWithPad
	d.CreatedAt = now
	d.ModifiedAt = now
	copy(d.Name[:], []byte("rootfs"))

	meta := sifPartitionExtra{FSType: 1, PartType: 2, Arch: sifArch(arch)}
	metaBytes, err := marshalLE(meta)
	if err != nil {
		return sifHeader{}, sifDescriptor{}, fmt.Errorf("encode partition descriptor metadata: %w", err)
	}
	copy(d.Extra[:], metaBytes)

	return h, d, nil
}

func writeSIFHeaderAndDescriptor(f *os.File, h sifHeader, d sifDescriptor) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek output file for SIF header: %w", err)
	}
	if err := binary.Write(f, binary.LittleEndian, &h); err != nil {
		return fmt.Errorf("write SIF header: %w", err)
	}
	if _, err := f.Seek(sifHeaderSize, io.SeekStart); err != nil {
		return fmt.Errorf("seek output file for SIF descriptor: %w", err)
	}
	if err := binary.Write(f, binary.LittleEndian, &d); err != nil {
		return fmt.Errorf("write SIF descriptor: %w", err)
	}
	return nil
}

func (ws *writeState) seekRelative(rel uint64) error {
	ws.relPos = rel
	_, err := ws.f.Seek(ws.base+int64(rel), io.SeekStart)
	if err != nil {
		return fmt.Errorf("seek output file: %w", err)
	}
	return nil
}

func (ws *writeState) write(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	n, err := ws.f.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	ws.relPos += uint64(n)
	return nil
}

func (ws *writeState) writeAt(rel uint64, value any) error {
	if _, err := ws.f.Seek(ws.base+int64(rel), io.SeekStart); err != nil {
		return fmt.Errorf("seek output file: %w", err)
	}
	if err := binary.Write(ws.f, binary.LittleEndian, value); err != nil {
		return err
	}
	_, err := ws.f.Seek(ws.base+int64(ws.relPos), io.SeekStart)
	if err != nil {
		return fmt.Errorf("restore output file position: %w", err)
	}
	return nil
}

func marshalLE(v any) ([]byte, error) {
	var b strings.Builder
	w := &stringWriter{b: &b}
	if err := binary.Write(w, binary.LittleEndian, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

type stringWriter struct {
	b *strings.Builder
}

func (w *stringWriter) Write(p []byte) (int, error) {
	return w.b.Write(p)
}

func normalizeArch(arch string) string {
	a := strings.TrimSpace(strings.ToLower(arch))
	if a == "" {
		a = runtime.GOARCH
	}
	switch a {
	case "x86_64":
		return "amd64"
	case "aarch64":
		return "arm64"
	default:
		return a
	}
}

func sifArch(arch string) [3]byte {
	switch normalizeArch(arch) {
	case "386":
		return [3]byte{'0', '1', 0}
	case "amd64":
		return [3]byte{'0', '2', 0}
	case "arm":
		return [3]byte{'0', '3', 0}
	case "arm64":
		return [3]byte{'0', '4', 0}
	case "ppc64":
		return [3]byte{'0', '5', 0}
	case "ppc64le":
		return [3]byte{'0', '6', 0}
	case "mips":
		return [3]byte{'0', '7', 0}
	case "mipsle":
		return [3]byte{'0', '8', 0}
	case "mips64":
		return [3]byte{'0', '9', 0}
	case "mips64le":
		return [3]byte{'1', '0', 0}
	case "s390x":
		return [3]byte{'1', '1', 0}
	case "riscv64":
		return [3]byte{'1', '2', 0}
	default:
		return [3]byte{'0', '0', 0}
	}
}

func toUnix32(t time.Time) uint32 {
	u := t.Unix()
	if u < 0 {
		return 0
	}
	if u > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(u)
}

func blockLog2(v uint32) uint16 {
	var n uint16
	for v > 1 {
		v >>= 1
		n++
	}
	return n
}

func alignUp(v int64, align int64) int64 {
	if align <= 1 {
		return v
	}
	mod := v % align
	if mod == 0 {
		return v
	}
	return v + align - mod
}
