package app

import (
	"fmt"
	"path/filepath"
	"strings"

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
