package oci

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const defaultRegistry = "https://registry-1.docker.io/v2"

var errUnsupportedDigest = errors.New("unsupported digest algorithm")

type Platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant"`
}

type Descriptor struct {
	MediaType string   `json:"mediaType"`
	Size      int64    `json:"size"`
	Digest    string   `json:"digest"`
	Platform  Platform `json:"platform"`
}

type Index struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []Descriptor `json:"manifests"`
}

type Manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}

type imageConfigMeta struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

type LayerFile struct {
	Digest    string `json:"digest"`
	MediaType string `json:"media_type"`
	Path      string `json:"path"`
}

type FetchResult struct {
	ImageRef          string      `json:"image_ref"`
	Architecture      string      `json:"architecture"`
	OutputDir         string      `json:"output_dir"`
	RootManifestPath  string      `json:"root_manifest_path"`
	ManifestPath      string      `json:"manifest_path"`
	ConfigPath        string      `json:"config_path"`
	Layers            []LayerFile `json:"layers"`
	ResolvedImageName string      `json:"resolved_image_name"`
	ResolvedRegistry  string      `json:"resolved_registry"`
	ResolvedReference string      `json:"resolved_reference"`
}

type PullResult struct {
	FetchResult FetchResult `json:"fetch_result"`
	RootFSDir   string      `json:"rootfs_dir"`
}

type Client struct {
	client *http.Client
}

type registrySession struct {
	client   *http.Client
	registry string
	token    string
}

type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
}

func NewClient() *Client {
	return &Client{
		client: &http.Client{
			Timeout: 0,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
			},
		},
	}
}

func HostArchitecture() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	default:
		return runtime.GOARCH
	}
}

func NormalizeArchitecture(arch string) (string, error) {
	a := strings.ToLower(strings.TrimSpace(arch))
	if a == "" {
		return HostArchitecture(), nil
	}

	switch a {
	case "amd64", "x86_64":
		return "amd64", nil
	case "arm64", "aarch64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("unsupported architecture %q", arch)
	}
}

// ParseImageRef parses an OCI image reference into registry, image name, and tag/digest reference.
func ParseImageRef(imageRef string) (registry string, image string, reference string, err error) {
	ref := strings.TrimSpace(imageRef)
	if ref == "" {
		return "", "", "", errors.New("image reference cannot be empty")
	}

	image = ref
	reference = "latest"

	if at := strings.LastIndex(image, "@"); at != -1 {
		image = image[:at]
		reference = ref[at+1:]
	} else {
		lastSlash := strings.LastIndex(image, "/")
		lastColon := strings.LastIndex(image, ":")
		if lastColon > lastSlash {
			image = image[:lastColon]
			reference = ref[lastColon+1:]
		}
	}

	if strings.TrimSpace(image) == "" {
		return "", "", "", fmt.Errorf("invalid image reference %q", imageRef)
	}
	if strings.TrimSpace(reference) == "" {
		return "", "", "", fmt.Errorf("empty tag/digest in image reference %q", imageRef)
	}

	firstSlash := strings.Index(image, "/")
	if firstSlash != -1 {
		firstComponent := image[:firstSlash]
		isHostname := strings.Contains(firstComponent, ".") ||
			strings.Contains(firstComponent, ":") ||
			firstComponent == "localhost"
		if isHostname {
			registry = firstComponent
			image = image[firstSlash+1:]
		}
	}

	if registry == "" {
		registry = defaultRegistry
	}

	if registry == "docker.io" {
		registry = defaultRegistry
	}

	if !strings.HasPrefix(registry, "http://") && !strings.HasPrefix(registry, "https://") {
		registry = "https://" + registry
	}

	if !strings.HasSuffix(registry, "/v2") {
		registry += "/v2"
	}

	if registry == defaultRegistry && !strings.Contains(image, "/") {
		image = "library/" + image
	}

	return registry, image, reference, nil
}

func (c *Client) Fetch(ctx context.Context, imageRef, arch, outDir string) (FetchResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(outDir) == "" {
		return FetchResult{}, errors.New("output directory is required")
	}

	normArch, err := NormalizeArchitecture(arch)
	if err != nil {
		return FetchResult{}, err
	}

	registry, imageName, reference, err := ParseImageRef(imageRef)
	if err != nil {
		return FetchResult{}, err
	}

	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return FetchResult{}, fmt.Errorf("resolve output directory: %w", err)
	}

	if err := os.MkdirAll(absOut, 0o755); err != nil {
		return FetchResult{}, fmt.Errorf("create output directory %s: %w", absOut, err)
	}

	sess := &registrySession{client: c.client, registry: registry}

	manifestRefPath := fmt.Sprintf("/%s/manifests/%s", imageName, reference)
	manifestAccept := []string{
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
	}

	rootManifestData, err := sess.downloadBytes(ctx, manifestRefPath, manifestAccept)
	if err != nil {
		return FetchResult{}, fmt.Errorf("fetch root manifest: %w", err)
	}

	rootManifestPath := filepath.Join(absOut, "manifest-root.json")
	if err := writeFile(rootManifestPath, rootManifestData, 0o644); err != nil {
		return FetchResult{}, err
	}

	manifestData := rootManifestData

	manifest, ok := decodeManifest(rootManifestData)
	if !ok {
		index, err := decodeIndex(rootManifestData)
		if err != nil {
			return FetchResult{}, fmt.Errorf("decode root manifest/index: %w", err)
		}
		desc, err := chooseManifestForArch(index, normArch)
		if err != nil {
			return FetchResult{}, err
		}

		manifestByDigestPath := fmt.Sprintf("/%s/manifests/%s", imageName, desc.Digest)
		manifestData, err = sess.downloadBytes(ctx, manifestByDigestPath,
			[]string{"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"})
		if err != nil {
			return FetchResult{}, fmt.Errorf("fetch selected manifest: %w", err)
		}

		manifest, ok = decodeManifest(manifestData)
		if !ok {
			return FetchResult{}, errors.New("selected manifest is not an OCI/Docker v2 manifest")
		}
	}

	manifestPath := filepath.Join(absOut, "manifest.json")
	if err := writeFile(manifestPath, manifestData, 0o644); err != nil {
		return FetchResult{}, err
	}

	if manifest.Config.Digest == "" {
		return FetchResult{}, errors.New("manifest missing config digest")
	}

	configPath := filepath.Join(absOut, "config"+configExtension(manifest.Config.MediaType))
	configBlobPath := fmt.Sprintf("/%s/blobs/%s", imageName, manifest.Config.Digest)
	if err := sess.downloadBlob(ctx, configBlobPath, []string{manifest.Config.MediaType, "application/octet-stream"}, manifest.Config.Digest, configPath); err != nil {
		return FetchResult{}, fmt.Errorf("fetch config %s: %w", manifest.Config.Digest, err)
	}
	cfgMeta, err := readConfigMeta(configPath)
	if err != nil {
		return FetchResult{}, err
	}
	if cfgMeta.Architecture != "" && !strings.EqualFold(cfgMeta.Architecture, normArch) {
		return FetchResult{}, fmt.Errorf(
			"requested architecture %q but resolved image config architecture is %q (image %s@%s)",
			normArch, cfgMeta.Architecture, imageName, reference,
		)
	}

	layersDir := filepath.Join(absOut, "layers")
	if err := os.MkdirAll(layersDir, 0o755); err != nil {
		return FetchResult{}, fmt.Errorf("create layers directory: %w", err)
	}

	result := FetchResult{
		ImageRef:          imageRef,
		Architecture:      normArch,
		OutputDir:         absOut,
		RootManifestPath:  rootManifestPath,
		ManifestPath:      manifestPath,
		ConfigPath:        configPath,
		ResolvedImageName: imageName,
		ResolvedRegistry:  registry,
		ResolvedReference: reference,
	}

	for i, layer := range manifest.Layers {
		if layer.Digest == "" {
			return FetchResult{}, fmt.Errorf("manifest layer %d missing digest", i)
		}

		layerFileName := fmt.Sprintf("%02d_%s%s", i+1, digestFileStem(layer.Digest), layerExtension(layer.MediaType))
		layerPath := filepath.Join(layersDir, layerFileName)
		layerBlobPath := fmt.Sprintf("/%s/blobs/%s", imageName, layer.Digest)
		if err := sess.downloadBlob(ctx, layerBlobPath, []string{layer.MediaType, "application/octet-stream"}, layer.Digest, layerPath); err != nil {
			return FetchResult{}, fmt.Errorf("fetch layer %s: %w", layer.Digest, err)
		}

		result.Layers = append(result.Layers, LayerFile{
			Digest:    layer.Digest,
			MediaType: layer.MediaType,
			Path:      layerPath,
		})
	}

	if err := writeJSON(filepath.Join(absOut, "fetch-result.json"), result); err != nil {
		return FetchResult{}, err
	}

	return result, nil
}

func (c *Client) Pull(ctx context.Context, imageRef, arch, outDir string) (PullResult, error) {
	if strings.TrimSpace(outDir) == "" {
		return PullResult{}, errors.New("output directory is required")
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return PullResult{}, fmt.Errorf("resolve output directory: %w", err)
	}
	if err := os.MkdirAll(absOut, 0o755); err != nil {
		return PullResult{}, fmt.Errorf("create output directory: %w", err)
	}

	artifactsDir := filepath.Join(absOut, "oci")
	fetchResult, err := c.Fetch(ctx, imageRef, arch, artifactsDir)
	if err != nil {
		return PullResult{}, err
	}

	rootFSDir := filepath.Join(absOut, "rootfs")
	if err := os.RemoveAll(rootFSDir); err != nil {
		return PullResult{}, fmt.Errorf("clear rootfs directory: %w", err)
	}
	if err := os.MkdirAll(rootFSDir, 0o755); err != nil {
		return PullResult{}, fmt.Errorf("create rootfs directory: %w", err)
	}

	for _, layer := range fetchResult.Layers {
		if err := applyLayer(layer.Path, layer.MediaType, rootFSDir); err != nil {
			return PullResult{}, fmt.Errorf("apply layer %s: %w", layer.Digest, err)
		}
	}

	result := PullResult{
		FetchResult: fetchResult,
		RootFSDir:   rootFSDir,
	}

	if err := writeJSON(filepath.Join(absOut, "pull-result.json"), result); err != nil {
		return PullResult{}, err
	}

	return result, nil
}

func (s *registrySession) downloadBytes(ctx context.Context, p string, accept []string) ([]byte, error) {
	resp, err := s.doRequest(ctx, http.MethodGet, p, accept)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return data, nil
}

func (s *registrySession) downloadBlob(ctx context.Context, p string, accept []string, digest, outPath string) error {
	if st, err := os.Stat(outPath); err == nil && st.Mode().IsRegular() {
		if digest == "" {
			return nil
		}
		if err := verifyFileDigest(outPath, digest); err == nil || errors.Is(err, errUnsupportedDigest) {
			return nil
		}
	}

	resp, err := s.doRequest(ctx, http.MethodGet, p, accept)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("create output directory for %s: %w", outPath, err)
	}

	tmpPath := outPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create temporary output file %s: %w", tmpPath, err)
	}

	algo, wantHex, ok := splitDigest(digest)
	var writer io.Writer = f
	var hasher hashWriter
	if ok && algo == "sha256" {
		h := sha256.New()
		hasher = h
		writer = io.MultiWriter(f, h)
	}

	if _, err := io.Copy(writer, resp.Body); err != nil {
		f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temporary file %s: %w", tmpPath, err)
	}

	if hasher != nil {
		gotHex := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(gotHex, wantHex) {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("digest mismatch for %s: expected %s got %s", outPath, wantHex, gotHex)
		}
	}

	if err := os.Rename(tmpPath, outPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("finalize %s: %w", outPath, err)
	}

	return nil
}

type hashWriter interface {
	Write(p []byte) (n int, err error)
	Sum(b []byte) []byte
}

func (s *registrySession) doRequest(ctx context.Context, method, p string, accept []string) (*http.Response, error) {
	const maxAttempts = 3

	for attempt := 0; attempt < maxAttempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, s.registry+p, nil)
		if err != nil {
			return nil, fmt.Errorf("build registry request: %w", err)
		}

		if s.token != "" {
			req.Header.Set("Authorization", "Bearer "+s.token)
		}
		for _, v := range accept {
			req.Header.Add("Accept", v)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			if attempt == maxAttempts-1 {
				return nil, fmt.Errorf("execute registry request: %w", err)
			}
			continue
		}

		if resp.StatusCode == http.StatusUnauthorized {
			authHeader := resp.Header.Get("Www-Authenticate")
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if err := s.refreshToken(ctx, authHeader); err != nil {
				return nil, err
			}
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
			resp.Body.Close()
			return nil, fmt.Errorf("registry request failed: %s (%s)", resp.Status, strings.TrimSpace(string(body)))
		}

		return resp, nil
	}

	return nil, errors.New("request failed after retries")
}

func (s *registrySession) refreshToken(ctx context.Context, authHeader string) error {
	params, err := parseAuthenticate(authHeader)
	if err != nil {
		return fmt.Errorf("parse authenticate header: %w", err)
	}

	realm := params["realm"]
	if realm == "" {
		return errors.New("authenticate header missing realm")
	}

	q := url.Values{}
	if service := params["service"]; service != "" {
		q.Set("service", service)
	}
	if scope := params["scope"]; scope != "" {
		q.Set("scope", scope)
	}

	tokenURL := realm
	if encoded := q.Encode(); encoded != "" {
		tokenURL += "?" + encoded
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return fmt.Errorf("build token request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("request registry token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return fmt.Errorf("token request failed: %s (%s)", resp.Status, strings.TrimSpace(string(body)))
	}

	var token tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return fmt.Errorf("decode token response: %w", err)
	}

	switch {
	case token.Token != "":
		s.token = token.Token
	case token.AccessToken != "":
		s.token = token.AccessToken
	default:
		return errors.New("token response missing token")
	}

	return nil
}

func parseAuthenticate(value string) (map[string]string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("missing authenticate header")
	}

	if i := strings.IndexByte(value, ' '); i > 0 && strings.EqualFold(value[:i], "Bearer") {
		value = strings.TrimSpace(value[i+1:])
	}

	parts := strings.Split(value, ",")
	out := make(map[string]string, len(parts))
	for _, part := range parts {
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("malformed authenticate segment %q", part)
		}
		out[strings.TrimSpace(key)] = strings.Trim(val, "\" ")
	}
	return out, nil
}

func decodeManifest(data []byte) (Manifest, bool) {
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, false
	}
	if manifest.Config.Digest == "" {
		return Manifest{}, false
	}
	return manifest, true
}

func decodeIndex(data []byte) (Index, error) {
	var index Index
	if err := json.Unmarshal(data, &index); err != nil {
		return Index{}, err
	}
	if len(index.Manifests) == 0 {
		return Index{}, errors.New("index has no manifests")
	}
	return index, nil
}

func chooseManifestForArch(index Index, arch string) (Descriptor, error) {
	for _, m := range index.Manifests {
		if strings.EqualFold(m.Platform.Architecture, arch) && (m.Platform.OS == "" || strings.EqualFold(m.Platform.OS, "linux")) {
			return m, nil
		}
	}
	for _, m := range index.Manifests {
		if strings.EqualFold(m.Platform.Architecture, arch) {
			return m, nil
		}
	}
	if len(index.Manifests) == 1 {
		return index.Manifests[0], nil
	}
	return Descriptor{}, fmt.Errorf("manifest for architecture %q not found", arch)
}

func configExtension(mediaType string) string {
	if strings.Contains(strings.ToLower(mediaType), "json") {
		return ".json"
	}
	return ".blob"
}

func layerExtension(mediaType string) string {
	lower := strings.ToLower(mediaType)
	switch {
	case strings.Contains(lower, "tar+gzip"), strings.Contains(lower, "diff.tar.gzip"):
		return ".tar.gz"
	case strings.Contains(lower, "tar") && strings.Contains(lower, "gzip"):
		return ".tar.gz"
	case strings.Contains(lower, "tar"):
		return ".tar"
	default:
		return ".blob"
	}
}

func compressionFromMediaType(mediaType string) (string, error) {
	lower := strings.ToLower(mediaType)
	switch {
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

func digestFileStem(digest string) string {
	algo, hexPart, ok := splitDigest(digest)
	if !ok {
		return sanitizeForFilename(digest)
	}
	return sanitizeForFilename(algo + "_" + hexPart)
}

func splitDigest(digest string) (algo string, hexPart string, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(strings.ToLower(digest)), ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func verifyFileDigest(filePath, digest string) error {
	algo, expected, ok := splitDigest(digest)
	if !ok {
		return fmt.Errorf("invalid digest %q", digest)
	}
	if algo != "sha256" {
		return errUnsupportedDigest
	}

	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("digest mismatch: expected %s got %s", expected, actual)
	}
	return nil
}

func writeFile(filePath string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return fmt.Errorf("create parent directory for %s: %w", filePath, err)
	}
	tmp := filePath + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", filePath, err)
	}
	if err := os.Rename(tmp, filePath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("finalize %s: %w", filePath, err)
	}
	return nil
}

func writeJSON(filePath string, value any) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", filePath, err)
	}
	b = append(b, '\n')
	return writeFile(filePath, b, 0o644)
}

func sanitizeForFilename(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "value"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "value"
	}
	return b.String()
}

func applyLayer(layerPath, mediaType, rootDir string) error {
	compression, err := compressionFromMediaType(mediaType)
	if err != nil {
		return err
	}

	f, err := os.Open(layerPath)
	if err != nil {
		return fmt.Errorf("open layer %s: %w", layerPath, err)
	}
	defer f.Close()

	var layerReader io.Reader = f
	var gz *gzip.Reader
	if compression == "gzip" {
		gz, err = gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("open gzip layer %s: %w", layerPath, err)
		}
		defer gz.Close()
		layerReader = gz
	}

	tr := tar.NewReader(layerReader)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry in %s: %w", layerPath, err)
		}

		cleanName := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if cleanName == "." || cleanName == "/" {
			continue
		}

		baseName := path.Base(cleanName)
		dirName := path.Dir(cleanName)
		if dirName == "." {
			dirName = ""
		}

		if baseName == ".wh..wh..opq" {
			dirTarget, err := safeJoin(rootDir, dirName)
			if err != nil {
				return err
			}
			if err := removeDirChildren(dirTarget); err != nil {
				return err
			}
			continue
		}

		if strings.HasPrefix(baseName, ".wh.") {
			removeName := path.Join(dirName, strings.TrimPrefix(baseName, ".wh."))
			target, err := safeJoin(rootDir, removeName)
			if err != nil {
				return err
			}
			if err := os.RemoveAll(target); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove whiteout target %s: %w", target, err)
			}
			continue
		}

		target, err := safeJoin(rootDir, cleanName)
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := ensureParentDir(target); err != nil {
				return err
			}
			if st, err := os.Lstat(target); err == nil && !st.IsDir() {
				if err := os.RemoveAll(target); err != nil {
					return fmt.Errorf("remove existing non-directory %s: %w", target, err)
				}
			}
			mode := os.FileMode(hdr.Mode)
			if mode == 0 {
				mode = 0o755
			}
			if err := os.MkdirAll(target, mode.Perm()); err != nil {
				return fmt.Errorf("create directory %s: %w", target, err)
			}
			if err := os.Chmod(target, mode); err != nil {
				return fmt.Errorf("chmod directory %s: %w", target, err)
			}
			if !hdr.ModTime.IsZero() {
				_ = os.Chtimes(target, hdr.ModTime, hdr.ModTime)
			}

		case tar.TypeReg, tar.TypeRegA:
			if err := ensureParentDir(target); err != nil {
				return err
			}
			if err := os.RemoveAll(target); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove existing path %s: %w", target, err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("write file %s: %w", target, err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("close file %s: %w", target, err)
			}
			mode := os.FileMode(hdr.Mode)
			if mode == 0 {
				mode = 0o644
			}
			if err := os.Chmod(target, mode); err != nil {
				return fmt.Errorf("chmod file %s: %w", target, err)
			}
			if !hdr.ModTime.IsZero() {
				_ = os.Chtimes(target, hdr.ModTime, hdr.ModTime)
			}

		case tar.TypeSymlink:
			if err := ensureParentDir(target); err != nil {
				return err
			}
			if err := os.RemoveAll(target); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove existing symlink target %s: %w", target, err)
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return fmt.Errorf("create symlink %s -> %s: %w", target, hdr.Linkname, err)
			}

		case tar.TypeLink:
			if err := ensureParentDir(target); err != nil {
				return err
			}
			if err := os.RemoveAll(target); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove existing hardlink target %s: %w", target, err)
			}
			linkTarget, err := safeJoin(rootDir, hdr.Linkname)
			if err != nil {
				return err
			}
			if err := os.Link(linkTarget, target); err != nil {
				return fmt.Errorf("create hardlink %s -> %s: %w", target, linkTarget, err)
			}

		case tar.TypeXHeader, tar.TypeXGlobalHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			continue

		default:
			continue
		}
	}
}

func safeJoin(rootDir, relPath string) (string, error) {
	cleanRel := path.Clean("/" + relPath)
	cleanRel = strings.TrimPrefix(cleanRel, "/")
	target := filepath.Join(rootDir, filepath.FromSlash(cleanRel))
	rel, err := filepath.Rel(rootDir, target)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", relPath, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes root", relPath)
	}
	return target, nil
}

func removeDirChildren(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("ensure opaque directory %s: %w", dir, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("list directory %s: %w", dir, err)
	}
	for _, entry := range entries {
		entryPath := filepath.Join(dir, entry.Name())
		if err := os.RemoveAll(entryPath); err != nil {
			return fmt.Errorf("remove opaque child %s: %w", entryPath, err)
		}
	}
	return nil
}

func ensureParentDir(filePath string) error {
	parent := filepath.Dir(filePath)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create parent directory %s: %w", parent, err)
	}
	return nil
}

func readConfigMeta(configPath string) (imageConfigMeta, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return imageConfigMeta{}, fmt.Errorf("read config %s: %w", configPath, err)
	}
	var meta imageConfigMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return imageConfigMeta{}, fmt.Errorf("decode config %s: %w", configPath, err)
	}
	return meta, nil
}
