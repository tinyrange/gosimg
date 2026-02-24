package image

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const (
	SIFHeaderSize     = 4096
	SIFDescriptorSize = 584
	SquashFSMagic     = "hsqs"
)

type SIFHeader struct {
	LaunchScript      string
	Magic             string
	VersionMajor      string
	VersionMinor      string
	UUID              [16]byte
	CreatedAt         int64
	ModifiedAt        int64
	DescriptorsFree   uint64
	DescriptorsTotal  uint64
	DescriptorsOffset uint64
	DescriptorsSize   uint64
	DataOffset        uint64
	DataSize          uint64
}

type SIFDescriptor struct {
	Index           int
	DataTypeRaw     uint32
	LayoutOffset    int
	Offset          uint64
	Size            uint64
	SizeWithPadding uint64
	Name            string
}

type File struct {
	Path               string
	F                  *os.File
	Size               uint64
	SIF                *SIFHeader
	Descriptors        []SIFDescriptor
	SquashFSOffset     int64
	SquashFSDescriptor *SIFDescriptor
}

func Open(p string) (*File, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	img := &File{Path: p, F: f, Size: uint64(st.Size())}

	head, err := ReadAtMost(f, 0, SIFHeaderSize)
	if err != nil {
		f.Close()
		return nil, err
	}

	if len(head) >= 42 && string(head[32:42]) == "SIF_MAGIC\x00" {
		h, err := parseSIFHeader(head)
		if err != nil {
			f.Close()
			return nil, err
		}
		img.SIF = &h
		desc, err := parseSIFDescriptors(f, img.Size, h)
		if err != nil {
			f.Close()
			return nil, err
		}
		img.Descriptors = desc
	}

	off, descriptor, err := findSquashFSOffset(img)
	if err != nil {
		f.Close()
		return nil, err
	}
	img.SquashFSOffset = off
	img.SquashFSDescriptor = descriptor
	return img, nil
}

func (f *File) Close() error {
	if f == nil || f.F == nil {
		return nil
	}
	return f.F.Close()
}

func parseSIFHeader(b []byte) (SIFHeader, error) {
	if len(b) < 128 {
		return SIFHeader{}, errors.New("short SIF header")
	}
	var h SIFHeader
	h.LaunchScript = trimCString(b[0:32])
	h.Magic = trimCString(b[32:42])
	h.VersionMajor = trimCString(b[42:45])
	h.VersionMinor = trimCString(b[45:48])
	copy(h.UUID[:], b[48:64])
	h.CreatedAt = int64(binary.LittleEndian.Uint64(b[64:72]))
	h.ModifiedAt = int64(binary.LittleEndian.Uint64(b[72:80]))
	h.DescriptorsFree = binary.LittleEndian.Uint64(b[80:88])
	h.DescriptorsTotal = binary.LittleEndian.Uint64(b[88:96])
	h.DescriptorsOffset = binary.LittleEndian.Uint64(b[96:104])
	h.DescriptorsSize = binary.LittleEndian.Uint64(b[104:112])
	h.DataOffset = binary.LittleEndian.Uint64(b[112:120])
	h.DataSize = binary.LittleEndian.Uint64(b[120:128])
	if h.Magic != "SIF_MAGIC" {
		return SIFHeader{}, fmt.Errorf("invalid SIF magic %q", h.Magic)
	}
	return h, nil
}

func parseSIFDescriptors(f *os.File, fileSize uint64, h SIFHeader) ([]SIFDescriptor, error) {
	if h.DescriptorsTotal == 0 {
		return nil, nil
	}
	maxByTable := int(h.DescriptorsTotal)
	bytesNeeded := uint64(maxByTable) * SIFDescriptorSize
	if h.DescriptorsOffset+bytesNeeded > fileSize {
		maxByTable = int((fileSize - h.DescriptorsOffset) / SIFDescriptorSize)
		if maxByTable < 0 {
			maxByTable = 0
		}
	}
	if maxByTable == 0 {
		return nil, nil
	}
	table, err := ReadAtMost(f, int64(h.DescriptorsOffset), maxByTable*SIFDescriptorSize)
	if err != nil {
		return nil, err
	}

	desc := make([]SIFDescriptor, 0, maxByTable)
	for i := 0; i < maxByTable; i++ {
		raw := table[i*SIFDescriptorSize : (i+1)*SIFDescriptorSize]
		d := inferDescriptor(i+1, raw, fileSize, h.DataOffset)
		if d == nil {
			continue
		}
		desc = append(desc, *d)
	}
	sort.Slice(desc, func(i, j int) bool { return desc[i].Offset < desc[j].Offset })
	return desc, nil
}

func inferDescriptor(idx int, raw []byte, fileSize uint64, dataOffset uint64) *SIFDescriptor {
	if len(raw) < SIFDescriptorSize {
		return nil
	}
	dtype := binary.LittleEndian.Uint32(raw[0:4])
	if dtype == 0 {
		return nil
	}

	bestPos := -1
	var bestOff, bestSize, bestPad uint64
	for p := 8; p+24 <= len(raw); p++ {
		off := binary.LittleEndian.Uint64(raw[p : p+8])
		sz := binary.LittleEndian.Uint64(raw[p+8 : p+16])
		pad := binary.LittleEndian.Uint64(raw[p+16 : p+24])
		if off == 0 || sz == 0 {
			continue
		}
		if off+sz > fileSize {
			continue
		}
		if pad < sz {
			continue
		}
		if off < dataOffset {
			continue
		}
		if bestPos == -1 || off < bestOff {
			bestPos = p
			bestOff = off
			bestSize = sz
			bestPad = pad
		}
	}
	if bestPos == -1 {
		return nil
	}

	name := guessName(raw[64:220])
	return &SIFDescriptor{
		Index:           idx,
		DataTypeRaw:     dtype,
		LayoutOffset:    bestPos,
		Offset:          bestOff,
		Size:            bestSize,
		SizeWithPadding: bestPad,
		Name:            name,
	}
}

func findSquashFSOffset(img *File) (int64, *SIFDescriptor, error) {
	if img.SIF != nil {
		for i := range img.Descriptors {
			d := &img.Descriptors[i]
			ok, err := hasMagicAt(img.F, int64(d.Offset), SquashFSMagic)
			if err != nil {
				return 0, nil, err
			}
			if ok {
				return int64(d.Offset), d, nil
			}
		}
		start := int64(img.SIF.DataOffset)
		off, err := ScanForMagic(img.F, start, SquashFSMagic)
		if err == nil {
			return off, nil, nil
		}
	}
	if ok, err := hasMagicAt(img.F, 0, SquashFSMagic); err == nil && ok {
		return 0, nil, nil
	}
	off, err := ScanForMagic(img.F, 0, SquashFSMagic)
	if err != nil {
		return 0, nil, errors.New("could not locate embedded squashfs")
	}
	return off, nil, nil
}

func ReadAtMost(f *os.File, off int64, n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("negative read length")
	}
	buf := make([]byte, n)
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func hasMagicAt(f *os.File, off int64, magic string) (bool, error) {
	b, err := ReadAtMost(f, off, len(magic))
	if err != nil {
		return false, err
	}
	return string(b) == magic, nil
}

func ScanForMagic(f *os.File, start int64, magic string) (int64, error) {
	const chunk = 1 << 20
	overlap := len(magic) - 1
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	end := st.Size()
	if start < 0 {
		start = 0
	}
	if start >= end {
		return 0, io.EOF
	}

	needle := []byte(magic)
	pos := start
	tail := []byte{}
	for pos < end {
		toRead := chunk
		if pos+int64(toRead) > end {
			toRead = int(end - pos)
		}
		part := make([]byte, toRead)
		if _, err := f.Seek(pos, io.SeekStart); err != nil {
			return 0, err
		}
		if _, err := io.ReadFull(f, part); err != nil {
			return 0, err
		}
		buf := append(tail, part...)
		if idx := bytes.Index(buf, needle); idx >= 0 {
			return pos - int64(len(tail)) + int64(idx), nil
		}
		if len(buf) > overlap {
			tail = append([]byte(nil), buf[len(buf)-overlap:]...)
		} else {
			tail = append([]byte(nil), buf...)
		}
		pos += int64(toRead)
	}
	return 0, io.EOF
}

func trimCString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}

func guessName(b []byte) string {
	best := ""
	i := 0
	for i < len(b) {
		for i < len(b) && !isPrintableASCII(b[i]) {
			i++
		}
		start := i
		for i < len(b) && isPrintableASCII(b[i]) {
			i++
		}
		if i-start >= 3 {
			candidate := string(b[start:i])
			if strings.ContainsAny(candidate, "/.:-_") && len(candidate) > len(best) {
				best = candidate
			}
		}
		i++
	}
	return best
}

func isPrintableASCII(c byte) bool {
	return c >= 32 && c <= 126
}
