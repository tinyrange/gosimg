package oci

import "testing"

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		name          string
		imageRef      string
		wantRegistry  string
		wantImage     string
		wantReference string
	}{
		{
			name:          "implicit docker hub library latest",
			imageRef:      "alpine",
			wantRegistry:  defaultRegistry,
			wantImage:     "library/alpine",
			wantReference: "latest",
		},
		{
			name:          "implicit docker hub with tag",
			imageRef:      "alpine:3.20",
			wantRegistry:  defaultRegistry,
			wantImage:     "library/alpine",
			wantReference: "3.20",
		},
		{
			name:          "docker io explicit",
			imageRef:      "docker.io/library/nginx:latest",
			wantRegistry:  defaultRegistry,
			wantImage:     "library/nginx",
			wantReference: "latest",
		},
		{
			name:          "custom registry and namespace",
			imageRef:      "ghcr.io/tinyrange/app:v1",
			wantRegistry:  "https://ghcr.io/v2",
			wantImage:     "tinyrange/app",
			wantReference: "v1",
		},
		{
			name:          "localhost with port",
			imageRef:      "localhost:5000/image:tag",
			wantRegistry:  "https://localhost:5000/v2",
			wantImage:     "image",
			wantReference: "tag",
		},
		{
			name:          "digest reference",
			imageRef:      "ubuntu@sha256:abcdef",
			wantRegistry:  defaultRegistry,
			wantImage:     "library/ubuntu",
			wantReference: "sha256:abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRegistry, gotImage, gotReference, err := ParseImageRef(tt.imageRef)
			if err != nil {
				t.Fatalf("ParseImageRef(%q) error = %v", tt.imageRef, err)
			}
			if gotRegistry != tt.wantRegistry {
				t.Fatalf("registry = %q, want %q", gotRegistry, tt.wantRegistry)
			}
			if gotImage != tt.wantImage {
				t.Fatalf("image = %q, want %q", gotImage, tt.wantImage)
			}
			if gotReference != tt.wantReference {
				t.Fatalf("reference = %q, want %q", gotReference, tt.wantReference)
			}
		})
	}
}

func TestNormalizeArchitecture(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "amd64", want: "amd64"},
		{in: "x86_64", want: "amd64"},
		{in: "arm64", want: "arm64"},
		{in: "aarch64", want: "arm64"},
		{in: "", want: HostArchitecture()},
		{in: "ppc64le", wantErr: true},
	}

	for _, tt := range tests {
		got, err := NormalizeArchitecture(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("NormalizeArchitecture(%q) expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizeArchitecture(%q) unexpected error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("NormalizeArchitecture(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
