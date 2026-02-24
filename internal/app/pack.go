package app

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/tinyrange/gosimg/internal/oci"
	"github.com/tinyrange/gosimg/internal/simg"
)

func RunPack(rootDir, outPath, arch string) error {
	if strings.TrimSpace(rootDir) == "" {
		return fmt.Errorf("root directory is required")
	}
	if strings.TrimSpace(outPath) == "" {
		return fmt.Errorf("output .simg path is required")
	}

	if err := simg.WriteFromDir(rootDir, outPath, arch); err != nil {
		return err
	}

	absOut, err := filepath.Abs(outPath)
	if err != nil {
		absOut = outPath
	}
	fmt.Printf("wrote: %s\n", absOut)
	return nil
}

func RunPackOCI(fetchDir, outPath, arch string) error {
	if strings.TrimSpace(fetchDir) == "" {
		return fmt.Errorf("fetched OCI directory is required")
	}
	if strings.TrimSpace(outPath) == "" {
		return fmt.Errorf("output .simg path is required")
	}

	if err := simg.WriteFromFetchDir(fetchDir, outPath, arch); err != nil {
		return err
	}

	absOut, err := filepath.Abs(outPath)
	if err != nil {
		absOut = outPath
	}
	fmt.Printf("wrote: %s\n", absOut)
	return nil
}

func RunPackRegistry(imageRef, outPath, arch string) error {
	if strings.TrimSpace(imageRef) == "" {
		return fmt.Errorf("image reference is required")
	}
	if strings.TrimSpace(outPath) == "" {
		return fmt.Errorf("output .simg path is required")
	}

	client := oci.NewClient()
	resolved, err := client.ResolveRemote(context.Background(), imageRef, arch)
	if err != nil {
		return err
	}

	layers := make([]simg.LayerSource, 0, len(resolved.Manifest.Layers))
	for i, desc := range resolved.Manifest.Layers {
		layerIndex := i
		layerName := desc.Digest
		if strings.TrimSpace(layerName) == "" {
			layerName = fmt.Sprintf("layer-%d", i)
		}
		layers = append(layers, simg.LayerSource{
			Name:      layerName,
			MediaType: desc.MediaType,
			Open: func() (io.ReadCloser, error) {
				rc, _, err := resolved.OpenLayer(context.Background(), layerIndex)
				return rc, err
			},
		})
	}

	if err := simg.WriteFromLayerSources(layers, outPath, resolved.Architecture); err != nil {
		return err
	}

	absOut, err := filepath.Abs(outPath)
	if err != nil {
		absOut = outPath
	}
	fmt.Printf("image: %s\n", resolved.ImageRef)
	fmt.Printf("arch: %s\n", resolved.Architecture)
	fmt.Printf("layers: %d\n", len(layers))
	fmt.Printf("wrote: %s\n", absOut)
	return nil
}
