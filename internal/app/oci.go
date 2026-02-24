package app

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/tinyrange/gosimg/internal/oci"
)

func RunOCIFetch(imageRef, arch, out string) error {
	if strings.TrimSpace(out) == "" {
		normArch, err := oci.NormalizeArchitecture(arch)
		if err != nil {
			return err
		}
		out = "fetch-" + sanitizeSegment(imageRef) + "-" + normArch
	}
	client := oci.NewClient()

	res, err := client.Fetch(context.Background(), imageRef, arch, out)
	if err != nil {
		return err
	}

	fmt.Printf("image: %s\n", res.ImageRef)
	fmt.Printf("arch: %s\n", res.Architecture)
	fmt.Printf("out: %s\n", res.OutputDir)
	fmt.Printf("root_manifest: %s\n", displayPath(res.RootManifestPath))
	fmt.Printf("manifest: %s\n", displayPath(res.ManifestPath))
	fmt.Printf("config: %s\n", displayPath(res.ConfigPath))
	fmt.Printf("layers: %d\n", len(res.Layers))
	for _, layer := range res.Layers {
		fmt.Printf("  - %s\n", displayPath(layer.Path))
	}
	return nil
}

func RunOCIPull(imageRef, arch, out string) error {
	if strings.TrimSpace(out) == "" {
		normArch, err := oci.NormalizeArchitecture(arch)
		if err != nil {
			return err
		}
		out = "pull-" + sanitizeSegment(imageRef) + "-" + normArch
	}
	client := oci.NewClient()

	res, err := client.Pull(context.Background(), imageRef, arch, out)
	if err != nil {
		return err
	}

	fmt.Printf("image: %s\n", res.FetchResult.ImageRef)
	fmt.Printf("arch: %s\n", res.FetchResult.Architecture)
	fmt.Printf("out: %s\n", displayPath(filepath.Dir(res.RootFSDir)))
	fmt.Printf("artifacts: %s\n", displayPath(res.FetchResult.OutputDir))
	fmt.Printf("rootfs: %s\n", displayPath(res.RootFSDir))
	fmt.Printf("layers_applied: %d\n", len(res.FetchResult.Layers))
	return nil
}

func RunOCIServe(fetchDir, addr string) error {
	fmt.Printf("fetch_dir: %s\n", displayPath(fetchDir))
	if strings.TrimSpace(addr) != "" {
		fmt.Printf("addr: %s\n", addr)
	}
	return oci.ServeFetchDir(fetchDir, addr)
}

func sanitizeSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "image"
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
		return "image"
	}
	return b.String()
}

func displayPath(p string) string {
	if p == "" {
		return ""
	}
	if rel, err := filepath.Rel(".", p); err == nil {
		if rel == "." {
			return "."
		}
		if !strings.HasPrefix(rel, "..") {
			return rel
		}
	}
	return p
}
