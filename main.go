package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/tinyrange/gosimg/internal/app"
)

func main() {
	if len(os.Args) < 3 {
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
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
