package simg

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type fetchResult struct {
	ImageRef      string       `json:"image_ref"`
	Architecture  string       `json:"architecture"`
	OutputDir     string       `json:"output_dir"`
	ConfigPath    string       `json:"config_path"`
	Layers        []fetchLayer `json:"layers"`
	ResolvedImage string       `json:"resolved_image_name"`
}

type fetchLayer struct {
	Digest    string `json:"digest"`
	MediaType string `json:"media_type"`
	Path      string `json:"path"`
}

func WriteFromFetchDir(fetchDir, outPath, arch string) error {
	if strings.TrimSpace(fetchDir) == "" {
		return fmt.Errorf("fetch directory is required")
	}
	if strings.TrimSpace(outPath) == "" {
		return fmt.Errorf("output path is required")
	}

	absFetch, err := filepath.Abs(fetchDir)
	if err != nil {
		return fmt.Errorf("resolve fetch directory: %w", err)
	}

	result, err := readFetchResult(absFetch)
	if err != nil {
		return err
	}

	metaArch := normalizeArch(result.Architecture)
	normArch := normalizeArch(arch)
	if strings.TrimSpace(arch) == "" {
		normArch = metaArch
	}
	if metaArch != "" && normArch != "" && metaArch != normArch {
		return fmt.Errorf("arch mismatch: requested %q, fetched image is %q", normArch, metaArch)
	}

	root, allNodes, err := buildTreeFromLayers(result.Layers)
	if err != nil {
		return err
	}

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

	ws := &writeState{f: f, base: squashOffset, relPos: 0}
	if err := ws.seekRelative(0); err != nil {
		return err
	}

	writeFiles := func(ws *writeState, inodes []*node) error {
		return writeFileDataFromLayers(ws, inodes, result.Layers)
	}

	squashSize, err := writeSquashFS(ws, root, allNodes, writeFiles)
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

func readFetchResult(fetchDir string) (*fetchResult, error) {
	resultPath := filepath.Join(fetchDir, "fetch-result.json")
	data, err := os.ReadFile(resultPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", resultPath, err)
	}
	var r fetchResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("decode %s: %w", resultPath, err)
	}
	if len(r.Layers) == 0 {
		return nil, fmt.Errorf("no layers in %s", resultPath)
	}

	for i := range r.Layers {
		p := r.Layers[i].Path
		if !filepath.IsAbs(p) {
			p = filepath.Join(fetchDir, p)
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, fmt.Errorf("resolve layer path %q: %w", p, err)
		}
		r.Layers[i].Path = abs
	}

	return &r, nil
}

func buildTreeFromLayers(layers []fetchLayer) (*node, []*node, error) {
	nodeByPath := map[string]*node{
		"": {
			name:  "",
			kind:  nodeDirectory,
			mode:  0o755 | os.ModeDir,
			mtime: toUnix32(time.Now()),
		},
	}

	for i, layer := range layers {
		rc, err := openLayerReader(layer)
		if err != nil {
			return nil, nil, err
		}

		tr := tar.NewReader(rc)
		seq := 0

		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				rc.Close()
				return nil, nil, fmt.Errorf("read tar header from %s: %w", layer.Path, err)
			}

			rel, err := cleanRelPath(hdr.Name)
			if err != nil {
				rc.Close()
				return nil, nil, fmt.Errorf("invalid path %q in %s: %w", hdr.Name, layer.Path, err)
			}
			if rel == "" {
				continue
			}

			base := path.Base(rel)
			dir := path.Dir(rel)
			if dir == "." {
				dir = ""
			}

			if base == ".wh..wh..opq" {
				opaqDir := dir
				ensureDirNode(nodeByPath, opaqDir, hdr.ModTime)
				removeChildren(nodeByPath, opaqDir)
				continue
			}

			if strings.HasPrefix(base, ".wh.") {
				victim := path.Join(dir, strings.TrimPrefix(base, ".wh."))
				removePathRecursive(nodeByPath, victim)
				continue
			}

			ensureDirNode(nodeByPath, dir, hdr.ModTime)

			switch hdr.Typeflag {
			case tar.TypeDir:
				upsertDirNode(nodeByPath, rel, hdr)
			case tar.TypeReg, tar.TypeRegA:
				seq++
				n := &node{
					name:         path.Base(rel),
					kind:         nodeRegular,
					mode:         os.FileMode(hdr.Mode),
					mtime:        toUnix32(hdr.ModTime),
					size:         uint64(hdr.Size),
					sourceKey:    sourceKey(i, seq),
					sourceLayer:  i,
					sourceSeq:    seq,
					sourceOrigin: true,
				}
				setNode(nodeByPath, rel, n)
			case tar.TypeSymlink:
				n := &node{
					name:  path.Base(rel),
					kind:  nodeSymlink,
					mode:  os.ModeSymlink | 0o777,
					mtime: toUnix32(hdr.ModTime),
					link:  hdr.Linkname,
				}
				setNode(nodeByPath, rel, n)
			case tar.TypeLink:
				target := resolveHardlinkTarget(nodeByPath, rel, hdr.Linkname)
				targetNode := nodeByPath[target]
				if targetNode == nil || targetNode.kind != nodeRegular || targetNode.sourceKey == "" {
					rc.Close()
					return nil, nil, fmt.Errorf("invalid hardlink %q -> %q in %s", rel, hdr.Linkname, layer.Path)
				}
				n := &node{
					name:         path.Base(rel),
					kind:         nodeRegular,
					mode:         os.FileMode(hdr.Mode),
					mtime:        toUnix32(hdr.ModTime),
					size:         targetNode.size,
					sourceKey:    targetNode.sourceKey,
					sourceLayer:  targetNode.sourceLayer,
					sourceSeq:    targetNode.sourceSeq,
					sourceOrigin: false,
				}
				setNode(nodeByPath, rel, n)
			default:
				continue
			}
		}

		if err := rc.Close(); err != nil {
			return nil, nil, fmt.Errorf("close layer %s: %w", layer.Path, err)
		}
	}

	root := nodeByPath[""]
	if root == nil {
		return nil, nil, fmt.Errorf("internal error: missing root node")
	}

	for _, n := range nodeByPath {
		n.children = nil
		n.parent = nil
	}

	keys := make([]string, 0, len(nodeByPath))
	for k := range nodeByPath {
		if k == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		di := strings.Count(keys[i], "/")
		dj := strings.Count(keys[j], "/")
		if di != dj {
			return di < dj
		}
		return keys[i] < keys[j]
	})

	for _, k := range keys {
		n := nodeByPath[k]
		parentKey := path.Dir(k)
		if parentKey == "." {
			parentKey = ""
		}
		p := nodeByPath[parentKey]
		if p == nil || p.kind != nodeDirectory {
			return nil, nil, fmt.Errorf("internal tree error: missing directory parent for %s", k)
		}
		n.parent = p
		if n.name == "" {
			n.name = path.Base(k)
		}
		p.children = append(p.children, n)
	}

	all := make([]*node, 0, len(nodeByPath))
	all = append(all, root)
	for _, k := range keys {
		all = append(all, nodeByPath[k])
	}
	for _, n := range all {
		if len(n.children) > 1 {
			sort.Slice(n.children, func(i, j int) bool { return n.children[i].name < n.children[j].name })
		}
	}

	return root, all, nil
}

func writeFileDataFromLayers(ws *writeState, inodes []*node, layers []fetchLayer) error {
	type record struct {
		startRel uint64
		blocks   []uint32
		written  bool
		size     uint64
	}

	required := make(map[string]*node)
	records := make(map[string]*record)

	for _, n := range inodes {
		if n.kind != nodeRegular {
			continue
		}
		if n.sourceKey == "" {
			n.fileStartRel = ws.relPos
			n.fileBlocks = nil
			continue
		}
		if _, ok := records[n.sourceKey]; !ok {
			records[n.sourceKey] = &record{size: n.size}
		}
		if n.sourceOrigin && n.size > 0 {
			required[n.sourceKey] = n
		}
	}

	buf := make([]byte, squashBlockSize)

	for layerIndex, layer := range layers {
		rc, err := openLayerReader(layer)
		if err != nil {
			return err
		}
		tr := tar.NewReader(rc)
		seq := 0

		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				rc.Close()
				return fmt.Errorf("read tar header from %s: %w", layer.Path, err)
			}

			if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
				continue
			}
			rel, err := cleanRelPath(hdr.Name)
			if err != nil {
				rc.Close()
				return fmt.Errorf("invalid path %q in %s: %w", hdr.Name, layer.Path, err)
			}
			if rel == "" {
				continue
			}
			base := path.Base(rel)
			if base == ".wh..wh..opq" || strings.HasPrefix(base, ".wh.") {
				continue
			}

			seq++
			key := sourceKey(layerIndex, seq)
			target := required[key]
			if target == nil {
				continue
			}
			rec := records[key]
			if rec == nil {
				rc.Close()
				return fmt.Errorf("missing source record for %s", key)
			}
			if rec.written {
				continue
			}

			rec.startRel = ws.relPos
			rec.blocks = rec.blocks[:0]

			remaining := target.size
			for remaining > 0 {
				chunk := len(buf)
				if remaining < uint64(chunk) {
					chunk = int(remaining)
				}
				n, err := io.ReadFull(tr, buf[:chunk])
				if err != nil {
					rc.Close()
					return fmt.Errorf("read file payload for %s from %s: %w", target.name, layer.Path, err)
				}
				if err := ws.write(buf[:n]); err != nil {
					rc.Close()
					return fmt.Errorf("write payload for %s: %w", target.name, err)
				}
				rec.blocks = append(rec.blocks, uint32(n)|squashDataUncompressed)
				remaining -= uint64(n)
			}

			rec.written = true
		}

		if err := rc.Close(); err != nil {
			return fmt.Errorf("close layer %s: %w", layer.Path, err)
		}
	}

	for key, n := range required {
		rec := records[key]
		if rec == nil || !rec.written {
			return fmt.Errorf("missing required file payload for %s (source %s)", n.name, key)
		}
	}

	for _, n := range inodes {
		if n.kind != nodeRegular || n.sourceKey == "" {
			continue
		}
		rec := records[n.sourceKey]
		if rec == nil {
			return fmt.Errorf("missing source record for %s", n.sourceKey)
		}
		n.fileStartRel = rec.startRel
		n.fileBlocks = append([]uint32(nil), rec.blocks...)
	}

	return nil
}

func sourceKey(layer, seq int) string {
	return fmt.Sprintf("%d:%d", layer, seq)
}

func ensureDirNode(nodeByPath map[string]*node, rel string, mtime time.Time) *node {
	rel = strings.TrimPrefix(rel, "/")
	rel = path.Clean(rel)
	if rel == "." {
		rel = ""
	}
	if rel == "" {
		return nodeByPath[""]
	}

	parts := strings.Split(rel, "/")
	cur := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		if cur == "" {
			cur = part
		} else {
			cur = cur + "/" + part
		}
		n := nodeByPath[cur]
		if n == nil {
			n = &node{name: part, kind: nodeDirectory, mode: 0o755 | os.ModeDir, mtime: toUnix32(mtime)}
			nodeByPath[cur] = n
			continue
		}
		if n.kind != nodeDirectory {
			removePathRecursive(nodeByPath, cur)
			n = &node{name: part, kind: nodeDirectory, mode: 0o755 | os.ModeDir, mtime: toUnix32(mtime)}
			nodeByPath[cur] = n
		}
	}
	return nodeByPath[rel]
}

func upsertDirNode(nodeByPath map[string]*node, rel string, hdr *tar.Header) {
	n := nodeByPath[rel]
	if n == nil {
		n = &node{name: path.Base(rel), kind: nodeDirectory}
		nodeByPath[rel] = n
	}
	if n.kind != nodeDirectory {
		removePathRecursive(nodeByPath, rel)
		n = &node{name: path.Base(rel), kind: nodeDirectory}
		nodeByPath[rel] = n
	}
	n.mode = os.FileMode(hdr.Mode) | os.ModeDir
	n.mtime = toUnix32(hdr.ModTime)
}

func setNode(nodeByPath map[string]*node, rel string, n *node) {
	if existing := nodeByPath[rel]; existing != nil {
		removePathRecursive(nodeByPath, rel)
	}
	nodeByPath[rel] = n
}

func removeChildren(nodeByPath map[string]*node, dir string) {
	if dir == "." {
		dir = ""
	}
	if dir == "" {
		for k := range nodeByPath {
			if k == "" {
				continue
			}
			delete(nodeByPath, k)
		}
		return
	}
	prefix := dir + "/"
	for k := range nodeByPath {
		if strings.HasPrefix(k, prefix) {
			delete(nodeByPath, k)
		}
	}
}

func removePathRecursive(nodeByPath map[string]*node, rel string) {
	rel = strings.TrimPrefix(rel, "/")
	if rel == "" {
		return
	}
	delete(nodeByPath, rel)
	prefix := rel + "/"
	for k := range nodeByPath {
		if strings.HasPrefix(k, prefix) {
			delete(nodeByPath, k)
		}
	}
}

func resolveHardlinkTarget(nodeByPath map[string]*node, relPath, linkname string) string {
	cand := normalizeHardlinkPath(linkname)
	if _, ok := nodeByPath[cand]; ok {
		return cand
	}
	dir := path.Dir(relPath)
	if dir == "." {
		dir = ""
	}
	joined := normalizeHardlinkPath(path.Join(dir, linkname))
	return joined
}

func normalizeHardlinkPath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "/")
	p = path.Clean(p)
	if p == "." {
		return ""
	}
	return p
}

func cleanRelPath(name string) (string, error) {
	clean := strings.TrimSpace(name)
	clean = strings.TrimPrefix(clean, "./")
	clean = strings.TrimPrefix(clean, "/")
	clean = path.Clean(clean)
	if clean == "." || clean == "" {
		return "", nil
	}
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("path escapes root")
	}
	return clean, nil
}

func openLayerReader(layer fetchLayer) (io.ReadCloser, error) {
	f, err := os.Open(layer.Path)
	if err != nil {
		return nil, fmt.Errorf("open layer %s: %w", layer.Path, err)
	}

	comp, err := layerCompression(layer.MediaType)
	if err != nil {
		f.Close()
		return nil, err
	}
	if comp == "none" {
		return f, nil
	}

	gr, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("open gzip layer %s: %w", layer.Path, err)
	}

	return &gzipLayerReader{f: f, gr: gr}, nil
}

func layerCompression(mediaType string) (string, error) {
	lower := strings.ToLower(strings.TrimSpace(mediaType))
	switch {
	case lower == "":
		return "gzip", nil
	case strings.Contains(lower, "tar+gzip"), strings.Contains(lower, "diff.tar.gzip"):
		return "gzip", nil
	case strings.Contains(lower, "tar") && strings.Contains(lower, "gzip"):
		return "gzip", nil
	case strings.Contains(lower, "tar"):
		return "none", nil
	default:
		return "", fmt.Errorf("unsupported layer media type %q", mediaType)
	}
}

type gzipLayerReader struct {
	f  *os.File
	gr *gzip.Reader
}

func (g *gzipLayerReader) Read(p []byte) (int, error) {
	return g.gr.Read(p)
}

func (g *gzipLayerReader) Close() error {
	err1 := g.gr.Close()
	err2 := g.f.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
