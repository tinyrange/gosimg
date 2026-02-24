package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/tinyrange/gosimg/internal/app"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	switch cmd {
	case "meta":
		if len(os.Args) != 3 {
			usage()
			os.Exit(2)
		}
		if err := app.RunMeta(os.Args[2]); err != nil {
			fatal(err)
		}
	case "ls":
		rc := flag.NewFlagSet("ls", flag.ContinueOnError)
		rc.SetOutput(io.Discard)
		recursive := rc.Bool("R", false, "recursive listing")
		if err := rc.Parse(os.Args[2:]); err != nil {
			fatal(err)
		}
		args := rc.Args()
		if len(args) < 1 || len(args) > 2 {
			usage()
			os.Exit(2)
		}
		image := args[0]
		target := "/"
		if len(args) == 2 {
			target = args[1]
		}
		if err := app.RunList(image, target, *recursive); err != nil {
			fatal(err)
		}
	case "extract":
		if len(os.Args) < 4 || len(os.Args) > 5 {
			usage()
			os.Exit(2)
		}
		image := os.Args[2]
		filePath := os.Args[3]
		out := ""
		if len(os.Args) == 5 {
			out = os.Args[4]
		}
		if err := app.RunExtract(image, filePath, out); err != nil {
			fatal(err)
		}
	case "fetch":
		fc := flag.NewFlagSet("fetch", flag.ContinueOnError)
		fc.SetOutput(io.Discard)
		arch := fc.String("arch", "", "target OCI architecture (default: host)")
		out := fc.String("out", "", "output directory (default: auto-generated)")
		if err := fc.Parse(os.Args[2:]); err != nil {
			fatal(err)
		}
		args := fc.Args()
		if len(args) != 1 {
			usage()
			os.Exit(2)
		}
		if err := app.RunOCIFetch(args[0], *arch, *out); err != nil {
			fatal(err)
		}
	case "pull":
		pc := flag.NewFlagSet("pull", flag.ContinueOnError)
		pc.SetOutput(io.Discard)
		arch := pc.String("arch", "", "target OCI architecture (default: host)")
		out := pc.String("out", "", "output directory (default: auto-generated)")
		if err := pc.Parse(os.Args[2:]); err != nil {
			fatal(err)
		}
		args := pc.Args()
		if len(args) != 1 {
			usage()
			os.Exit(2)
		}
		if err := app.RunOCIPull(args[0], *arch, *out); err != nil {
			fatal(err)
		}
	case "serve":
		sc := flag.NewFlagSet("serve", flag.ContinueOnError)
		sc.SetOutput(io.Discard)
		addr := sc.String("addr", "127.0.0.1:5000", "local listen address")
		if err := sc.Parse(os.Args[2:]); err != nil {
			fatal(err)
		}
		args := sc.Args()
		if len(args) != 1 {
			usage()
			os.Exit(2)
		}
		if err := app.RunOCIServe(args[0], *addr); err != nil {
			fatal(err)
		}
	case "pack":
		pk := flag.NewFlagSet("pack", flag.ContinueOnError)
		pk.SetOutput(io.Discard)
		arch := pk.String("arch", "", "target image architecture metadata (default: host)")
		cpuProfile := pk.String("cpuprofile", "", "write CPU profile to file")
		memProfile := pk.String("memprofile", "", "write heap profile to file")
		if err := pk.Parse(os.Args[2:]); err != nil {
			fatal(err)
		}
		args := pk.Args()
		if len(args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := runWithProfiles(*cpuProfile, *memProfile, func() error {
			return app.RunPack(args[0], args[1], *arch)
		}); err != nil {
			fatal(err)
		}
	case "pack-oci":
		pk := flag.NewFlagSet("pack-oci", flag.ContinueOnError)
		pk.SetOutput(io.Discard)
		arch := pk.String("arch", "", "target image architecture metadata (default: fetched arch)")
		cpuProfile := pk.String("cpuprofile", "", "write CPU profile to file")
		memProfile := pk.String("memprofile", "", "write heap profile to file")
		if err := pk.Parse(os.Args[2:]); err != nil {
			fatal(err)
		}
		args := pk.Args()
		if len(args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := runWithProfiles(*cpuProfile, *memProfile, func() error {
			return app.RunPackOCI(args[0], args[1], *arch)
		}); err != nil {
			fatal(err)
		}
	case "pack-registry":
		pk := flag.NewFlagSet("pack-registry", flag.ContinueOnError)
		pk.SetOutput(io.Discard)
		arch := pk.String("arch", "", "target OCI architecture (default: host)")
		cpuProfile := pk.String("cpuprofile", "", "write CPU profile to file")
		memProfile := pk.String("memprofile", "", "write heap profile to file")
		if err := pk.Parse(os.Args[2:]); err != nil {
			fatal(err)
		}
		args := pk.Args()
		if len(args) != 2 {
			usage()
			os.Exit(2)
		}
		if err := runWithProfiles(*cpuProfile, *memProfile, func() error {
			return app.RunPackRegistry(args[0], args[1], *arch)
		}); err != nil {
			fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "  gosimg meta <image.simg>\n")
	fmt.Fprintf(os.Stderr, "  gosimg ls [-R] <image.simg> [path]\n")
	fmt.Fprintf(os.Stderr, "  gosimg extract <image.simg> <path/in/squashfs> [output-file]\n")
	fmt.Fprintf(os.Stderr, "  gosimg fetch [-arch amd64|arm64] [-out dir] <oci-image-ref>\n")
	fmt.Fprintf(os.Stderr, "  gosimg pull [-arch amd64|arm64] [-out dir] <oci-image-ref>\n")
	fmt.Fprintf(os.Stderr, "  gosimg serve [-addr 127.0.0.1:5000] <fetched-oci-dir>\n")
	fmt.Fprintf(os.Stderr, "  gosimg pack [-arch <goarch>] [-cpuprofile file] [-memprofile file] <rootfs-dir> <out.simg>\n")
	fmt.Fprintf(os.Stderr, "  gosimg pack-oci [-arch <goarch>] [-cpuprofile file] [-memprofile file] <fetched-oci-dir> <out.simg>\n")
	fmt.Fprintf(os.Stderr, "  gosimg pack-registry [-arch amd64|arm64] [-cpuprofile file] [-memprofile file] <oci-image-ref> <out.simg>\n")
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

func runWithProfiles(cpuPath, memPath string, run func() error) error {
	var cpuFile *os.File

	if cpuPath != "" {
		f, err := os.Create(cpuPath)
		if err != nil {
			return fmt.Errorf("create CPU profile %q: %w", cpuPath, err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			f.Close()
			return fmt.Errorf("start CPU profile: %w", err)
		}
		cpuFile = f
	}

	runErr := run()

	if cpuFile != nil {
		pprof.StopCPUProfile()
		if err := cpuFile.Close(); err != nil {
			if runErr != nil {
				return runErr
			}
			return fmt.Errorf("close CPU profile %q: %w", cpuPath, err)
		}
	}

	if runErr != nil {
		return runErr
	}

	if memPath != "" {
		runtime.GC()
		f, err := os.Create(memPath)
		if err != nil {
			return fmt.Errorf("create heap profile %q: %w", memPath, err)
		}
		if err := pprof.WriteHeapProfile(f); err != nil {
			f.Close()
			return fmt.Errorf("write heap profile %q: %w", memPath, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close heap profile %q: %w", memPath, err)
		}
	}

	return nil
}
