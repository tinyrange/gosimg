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

type LayerSource struct {
	Name      string
	MediaType string
	Open      func() (io.ReadCloser, error)
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

	layers := make([]LayerSource, 0, len(result.Layers))
	for _, layer := range result.Layers {
		layerPath := layer.Path
		layers = append(layers, LayerSource{
			Name:      layerPath,
			MediaType: layer.MediaType,
			Open: func() (io.ReadCloser, error) {
				f, err := os.Open(layerPath)
				if err != nil {
					return nil, fmt.Errorf("open layer %s: %w", layerPath, err)
				}
				return f, nil
			},
		})
	}

	return WriteFromLayerSources(layers, outPath, normArch)
}

func WriteFromLayerSources(layers []LayerSource, outPath, arch string) error {
	if len(layers) == 0 {
		return fmt.Errorf("at least one OCI layer is required")
	}
	if strings.TrimSpace(outPath) == "" {
		return fmt.Errorf("output path is required")
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

	ws := &writeState{f: f, base: squashOffset, relPos: 0}
	if err := ws.seekRelative(0); err != nil {
		return err
	}

	if err := reserveSquashSuperblock(ws); err != nil {
		return err
	}

	root, allNodes, err := buildTreeAndWriteDataFromLayers(ws, layers)
	if err != nil {
		return err
	}

	squashSize, err := writeSquashFSPrepared(ws, root, allNodes)
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

func buildTreeAndWriteDataFromLayers(ws *writeState, layers []LayerSource) (*node, []*node, error) {
	root := &node{
		name:  "",
		kind:  nodeDirectory,
		mode:  0o755 | os.ModeDir,
		mtime: toUnix32(time.Now()),
	}
	nodeByPath := map[string]*node{"": root}
	ownerByPath := map[string]int{"": len(layers)}

	whiteoutPath := make(map[string]int)
	opaqueDir := make(map[string]int)

	buf := make([]byte, squashBlockSize)

	for layerIndex := len(layers) - 1; layerIndex >= 0; layerIndex-- {
		layer := layers[layerIndex]
		rc, err := openLayerStream(layer)
		if err != nil {
			return nil, nil, err
		}

		tr := tar.NewReader(rc)
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				rc.Close()
				return nil, nil, fmt.Errorf("read tar header from %s: %w", layer.Name, err)
			}

			rel, err := cleanRelPath(hdr.Name)
			if err != nil {
				rc.Close()
				return nil, nil, fmt.Errorf("invalid path %q in %s: %w", hdr.Name, layer.Name, err)
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
				ensureDirAtLayer(nodeByPath, ownerByPath, dir, hdr.ModTime, layerIndex)
				removeOwnedChildren(nodeByPath, ownerByPath, dir, layerIndex)
				setLayerMarker(opaqueDir, dir, layerIndex)
				continue
			}

			if strings.HasPrefix(base, ".wh.") {
				victim := path.Join(dir, strings.TrimPrefix(base, ".wh."))
				removeOwnedSubtree(nodeByPath, ownerByPath, victim, layerIndex)
				setLayerMarker(whiteoutPath, victim, layerIndex)
				continue
			}

			if pathBlockedByHigherLayers(rel, layerIndex, nodeByPath, ownerByPath, whiteoutPath, opaqueDir) {
				continue
			}

			ensureDirAtLayer(nodeByPath, ownerByPath, dir, hdr.ModTime, layerIndex)

			switch hdr.Typeflag {
			case tar.TypeDir:
				n := &node{
					name:  path.Base(rel),
					kind:  nodeDirectory,
					mode:  os.FileMode(hdr.Mode) | os.ModeDir,
					mtime: toUnix32(hdr.ModTime),
				}
				setNodeAtLayer(nodeByPath, ownerByPath, rel, n, layerIndex)

			case tar.TypeReg, tar.TypeRegA:
				if hdr.Size < 0 {
					rc.Close()
					return nil, nil, fmt.Errorf("negative file size for %s in %s", rel, layer.Name)
				}

				startRel := ws.relPos
				blocks := make([]uint32, 0, int((hdr.Size+int64(squashBlockSize)-1)/int64(squashBlockSize)))
				remaining := uint64(hdr.Size)
				for remaining > 0 {
					chunk := len(buf)
					if remaining < uint64(chunk) {
						chunk = int(remaining)
					}
					nr, err := io.ReadFull(tr, buf[:chunk])
					if err != nil {
						rc.Close()
						return nil, nil, fmt.Errorf("read file payload for %s from %s: %w", rel, layer.Name, err)
					}
					if err := ws.write(buf[:nr]); err != nil {
						rc.Close()
						return nil, nil, fmt.Errorf("write file payload for %s: %w", rel, err)
					}
					blocks = append(blocks, uint32(nr)|squashDataUncompressed)
					remaining -= uint64(nr)
				}

				n := &node{
					name:         path.Base(rel),
					kind:         nodeRegular,
					mode:         os.FileMode(hdr.Mode),
					mtime:        toUnix32(hdr.ModTime),
					size:         uint64(hdr.Size),
					fileStartRel: startRel,
					fileBlocks:   blocks,
				}
				setNodeAtLayer(nodeByPath, ownerByPath, rel, n, layerIndex)

			case tar.TypeSymlink:
				linkMode := os.FileMode(hdr.Mode & 0o777)
				if linkMode == 0 {
					linkMode = 0o777
				}
				n := &node{
					name:  path.Base(rel),
					kind:  nodeSymlink,
					mode:  os.ModeSymlink | linkMode,
					mtime: toUnix32(hdr.ModTime),
					link:  hdr.Linkname,
				}
				setNodeAtLayer(nodeByPath, ownerByPath, rel, n, layerIndex)

			case tar.TypeLink:
				target := resolveHardlinkTarget(nodeByPath, rel, hdr.Linkname)
				targetNode := nodeByPath[target]
				if targetNode == nil || targetNode.kind != nodeRegular {
					rc.Close()
					return nil, nil, fmt.Errorf("invalid hardlink %q -> %q in %s", rel, hdr.Linkname, layer.Name)
				}
				n := &node{
					name:         path.Base(rel),
					kind:         nodeRegular,
					mode:         os.FileMode(hdr.Mode),
					mtime:        toUnix32(hdr.ModTime),
					size:         targetNode.size,
					fileStartRel: targetNode.fileStartRel,
					fileBlocks:   append([]uint32(nil), targetNode.fileBlocks...),
				}
				setNodeAtLayer(nodeByPath, ownerByPath, rel, n, layerIndex)

			default:
				continue
			}
		}

		if err := rc.Close(); err != nil {
			return nil, nil, fmt.Errorf("close layer %s: %w", layer.Name, err)
		}
	}

	return finalizeNodeTree(nodeByPath)
}

func finalizeNodeTree(nodeByPath map[string]*node) (*node, []*node, error) {
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

func setLayerMarker(markers map[string]int, rel string, layer int) {
	rel = normalizeHardlinkPath(rel)
	if prev, ok := markers[rel]; ok && prev >= layer {
		return
	}
	markers[rel] = layer
}

func pathBlockedByHigherLayers(rel string, layer int, nodeByPath map[string]*node, ownerByPath, whiteoutPath, opaqueDir map[string]int) bool {
	if rel == "" {
		return false
	}

	if owner, ok := ownerByPath[rel]; ok && owner > layer {
		return true
	}

	if rootOpaque, ok := opaqueDir[""]; ok && rootOpaque > layer {
		return true
	}

	cur := rel
	for {
		if markLayer, ok := whiteoutPath[cur]; ok && markLayer > layer {
			return true
		}

		parent := path.Dir(cur)
		if parent == "." {
			parent = ""
		}
		if parent == cur {
			break
		}
		if parent != "" {
			if owner, ok := ownerByPath[parent]; ok && owner > layer {
				p := nodeByPath[parent]
				if p != nil && p.kind != nodeDirectory {
					return true
				}
			}
		}
		if parent == "" {
			break
		}
		cur = parent
	}

	cur = path.Dir(rel)
	if cur == "." {
		cur = ""
	}
	for cur != "" {
		if markLayer, ok := opaqueDir[cur]; ok && markLayer > layer {
			return true
		}
		parent := path.Dir(cur)
		if parent == "." {
			parent = ""
		}
		if parent == cur {
			break
		}
		cur = parent
	}

	return false
}

func ensureDirAtLayer(nodeByPath map[string]*node, ownerByPath map[string]int, rel string, mtime time.Time, layer int) {
	rel = normalizeHardlinkPath(rel)
	if rel == "" {
		return
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

		existing := nodeByPath[cur]
		existingLayer := ownerByPath[cur]
		if existing != nil && existingLayer > layer {
			if existing.kind != nodeDirectory {
				return
			}
			continue
		}

		if existing != nil && existingLayer == layer {
			if existing.kind == nodeDirectory {
				continue
			}
			removeOwnedSubtree(nodeByPath, ownerByPath, cur, layer)
			existing = nil
		}

		if existing == nil {
			nodeByPath[cur] = &node{
				name:  part,
				kind:  nodeDirectory,
				mode:  0o755 | os.ModeDir,
				mtime: toUnix32(mtime),
			}
			ownerByPath[cur] = layer
		}
	}
}

func setNodeAtLayer(nodeByPath map[string]*node, ownerByPath map[string]int, rel string, n *node, layer int) {
	rel = normalizeHardlinkPath(rel)
	if rel == "" {
		return
	}

	if existingLayer, ok := ownerByPath[rel]; ok {
		if existingLayer > layer {
			return
		}
		if existingLayer == layer {
			removeOwnedSubtree(nodeByPath, ownerByPath, rel, layer)
		} else {
			delete(nodeByPath, rel)
			delete(ownerByPath, rel)
		}
	}

	nodeByPath[rel] = n
	ownerByPath[rel] = layer
}

func removeOwnedChildren(nodeByPath map[string]*node, ownerByPath map[string]int, dir string, layer int) {
	dir = normalizeHardlinkPath(dir)
	if dir == "" {
		for p, own := range ownerByPath {
			if p == "" || own != layer {
				continue
			}
			delete(ownerByPath, p)
			delete(nodeByPath, p)
		}
		return
	}

	prefix := dir + "/"
	for p, own := range ownerByPath {
		if own != layer {
			continue
		}
		if strings.HasPrefix(p, prefix) {
			delete(ownerByPath, p)
			delete(nodeByPath, p)
		}
	}
}

func removeOwnedSubtree(nodeByPath map[string]*node, ownerByPath map[string]int, rel string, layer int) {
	rel = normalizeHardlinkPath(rel)
	if rel == "" {
		return
	}

	if own, ok := ownerByPath[rel]; ok && own == layer {
		delete(ownerByPath, rel)
		delete(nodeByPath, rel)
	}

	prefix := rel + "/"
	for p, own := range ownerByPath {
		if own != layer {
			continue
		}
		if strings.HasPrefix(p, prefix) {
			delete(ownerByPath, p)
			delete(nodeByPath, p)
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

func openLayerStream(layer LayerSource) (io.ReadCloser, error) {
	if layer.Open == nil {
		return nil, fmt.Errorf("layer %s has no opener", layer.Name)
	}

	rc, err := layer.Open()
	if err != nil {
		return nil, err
	}

	comp, err := layerCompression(layer.MediaType)
	if err != nil {
		rc.Close()
		return nil, err
	}
	if comp == "none" {
		return rc, nil
	}

	gr, err := gzip.NewReader(rc)
	if err != nil {
		rc.Close()
		return nil, fmt.Errorf("open gzip layer %s: %w", layer.Name, err)
	}

	return &gzipLayerReader{rc: rc, gr: gr}, nil
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
	rc io.Closer
	gr *gzip.Reader
}

func (g *gzipLayerReader) Read(p []byte) (int, error) {
	return g.gr.Read(p)
}

func (g *gzipLayerReader) Close() error {
	err1 := g.gr.Close()
	err2 := g.rc.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
