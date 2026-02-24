package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultManifestMediaType = "application/vnd.docker.distribution.manifest.v2+json"
	manifestPrefix           = "/manifests/"
	blobPrefix               = "/blobs/"
)

type localBlob struct {
	Digest    string
	MediaType string
	Path      string
	Size      int64
}

type localRegistryImage struct {
	Name string
	Tag  string

	RootManifestDigest    string
	RootManifestMediaType string
	RootManifestBody      []byte

	ManifestDigest    string
	ManifestMediaType string
	ManifestBody      []byte

	Blobs map[string]localBlob
}

type registryServer struct {
	img localRegistryImage
}

func ServeFetchDir(fetchDir, addr string) error {
	if strings.TrimSpace(fetchDir) == "" {
		return errors.New("fetch directory is required")
	}
	if strings.TrimSpace(addr) == "" {
		addr = "127.0.0.1:5000"
	}

	img, err := loadLocalRegistryImage(fetchDir)
	if err != nil {
		return err
	}

	fmt.Printf("serving image: %s:%s\n", img.Name, img.Tag)
	fmt.Printf("listen: http://%s\n", addr)
	fmt.Printf("manifest: /v2/%s/manifests/%s\n", img.Name, img.Tag)

	server := &http.Server{
		Addr:    addr,
		Handler: &registryServer{img: img},
	}
	return server.ListenAndServe()
}

func (s *registryServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v2" || r.URL.Path == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/v2/") {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/v2/")
	if repo, ref, ok := cutReferencePath(path, manifestPrefix); ok {
		s.serveManifest(w, r, repo, ref)
		return
	}
	if repo, digest, ok := cutReferencePath(path, blobPrefix); ok {
		s.serveBlob(w, r, repo, digest)
		return
	}

	http.NotFound(w, r)
}

func (s *registryServer) serveManifest(w http.ResponseWriter, r *http.Request, repo, ref string) {
	if repo != s.img.Name {
		http.NotFound(w, r)
		return
	}

	var body []byte
	var digest string
	var mediaType string

	switch ref {
	case s.img.Tag, s.img.RootManifestDigest:
		body = s.img.RootManifestBody
		digest = s.img.RootManifestDigest
		mediaType = s.img.RootManifestMediaType
	case s.img.ManifestDigest:
		body = s.img.ManifestBody
		digest = s.img.ManifestDigest
		mediaType = s.img.ManifestMediaType
	default:
		http.NotFound(w, r)
		return
	}

	serveBody(w, r, body, digest, mediaType)
}

func (s *registryServer) serveBlob(w http.ResponseWriter, r *http.Request, repo, digest string) {
	if repo != s.img.Name {
		http.NotFound(w, r)
		return
	}

	blob, ok := s.img.Blobs[strings.ToLower(strings.TrimSpace(digest))]
	if !ok {
		http.NotFound(w, r)
		return
	}

	f, err := os.Open(blob.Path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	w.Header().Set("Docker-Content-Digest", blob.Digest)
	if blob.MediaType != "" {
		w.Header().Set("Content-Type", blob.MediaType)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	if blob.Size >= 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", blob.Size))
	}

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

func loadLocalRegistryImage(fetchDir string) (localRegistryImage, error) {
	absDir, err := filepath.Abs(fetchDir)
	if err != nil {
		return localRegistryImage{}, fmt.Errorf("resolve fetch directory: %w", err)
	}

	resultPath := filepath.Join(absDir, "fetch-result.json")
	resultData, err := os.ReadFile(resultPath)
	if err != nil {
		return localRegistryImage{}, fmt.Errorf("read %s: %w", resultPath, err)
	}

	var result FetchResult
	if err := json.Unmarshal(resultData, &result); err != nil {
		return localRegistryImage{}, fmt.Errorf("decode %s: %w", resultPath, err)
	}

	rootManifestPath := filepath.Join(absDir, "manifest-root.json")
	rootManifest, err := os.ReadFile(rootManifestPath)
	if err != nil {
		return localRegistryImage{}, fmt.Errorf("read %s: %w", rootManifestPath, err)
	}

	manifestPath := filepath.Join(absDir, "manifest.json")
	manifestBody, err := os.ReadFile(manifestPath)
	if err != nil {
		return localRegistryImage{}, fmt.Errorf("read %s: %w", manifestPath, err)
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestBody, &manifest); err != nil {
		return localRegistryImage{}, fmt.Errorf("decode %s: %w", manifestPath, err)
	}

	rootMediaType := detectMediaType(rootManifest)
	manifestMediaType := manifest.MediaType
	if manifestMediaType == "" {
		manifestMediaType = defaultManifestMediaType
	}

	layersByDigest := make(map[string]LayerFile, len(result.Layers))
	for _, layer := range result.Layers {
		layersByDigest[strings.ToLower(layer.Digest)] = layer
	}

	blobs := make(map[string]localBlob, len(result.Layers)+1)

	cfgDigest := strings.ToLower(strings.TrimSpace(manifest.Config.Digest))
	if cfgDigest == "" {
		return localRegistryImage{}, errors.New("manifest missing config digest")
	}
	cfgInfo, err := statBlob(result.ConfigPath)
	if err != nil {
		return localRegistryImage{}, err
	}
	blobs[cfgDigest] = localBlob{
		Digest:    manifest.Config.Digest,
		MediaType: manifest.Config.MediaType,
		Path:      result.ConfigPath,
		Size:      cfgInfo.Size,
	}

	for _, layer := range manifest.Layers {
		digest := strings.ToLower(strings.TrimSpace(layer.Digest))
		entry, ok := layersByDigest[digest]
		if !ok {
			return localRegistryImage{}, fmt.Errorf("missing fetched layer for digest %s", layer.Digest)
		}
		info, err := statBlob(entry.Path)
		if err != nil {
			return localRegistryImage{}, err
		}
		mediaType := layer.MediaType
		if mediaType == "" {
			mediaType = entry.MediaType
		}
		blobs[digest] = localBlob{
			Digest:    layer.Digest,
			MediaType: mediaType,
			Path:      entry.Path,
			Size:      info.Size,
		}
	}

	tag := result.ResolvedReference
	if tag == "" {
		tag = "latest"
	}
	name := result.ResolvedImageName
	if name == "" {
		_, parsedName, _, err := ParseImageRef(result.ImageRef)
		if err != nil {
			return localRegistryImage{}, fmt.Errorf("parse image ref %q: %w", result.ImageRef, err)
		}
		name = parsedName
	}

	return localRegistryImage{
		Name:                  name,
		Tag:                   tag,
		RootManifestDigest:    digestOf(rootManifest),
		RootManifestMediaType: rootMediaType,
		RootManifestBody:      rootManifest,
		ManifestDigest:        digestOf(manifestBody),
		ManifestMediaType:     manifestMediaType,
		ManifestBody:          manifestBody,
		Blobs:                 blobs,
	}, nil
}

type fileInfo struct {
	Size int64
}

func statBlob(path string) (fileInfo, error) {
	st, err := os.Stat(path)
	if err != nil {
		return fileInfo{}, fmt.Errorf("stat blob %s: %w", path, err)
	}
	if !st.Mode().IsRegular() {
		return fileInfo{}, fmt.Errorf("blob %s is not a regular file", path)
	}
	return fileInfo{Size: st.Size()}, nil
}

func detectMediaType(data []byte) string {
	var probe struct {
		MediaType string `json:"mediaType"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return defaultManifestMediaType
	}
	if probe.MediaType == "" {
		return defaultManifestMediaType
	}
	return probe.MediaType
}

func cutReferencePath(path, token string) (repo string, ref string, ok bool) {
	i := strings.Index(path, token)
	if i <= 0 {
		return "", "", false
	}
	repo = path[:i]
	ref = path[i+len(token):]
	if repo == "" || ref == "" {
		return "", "", false
	}
	return repo, ref, true
}

func serveBody(w http.ResponseWriter, r *http.Request, body []byte, digest, mediaType string) {
	if mediaType == "" {
		mediaType = defaultManifestMediaType
	}
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
