package config

import (
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Loader provides configuration loading capabilities. It abstracts the source
// of configuration to allow for different implementations like files, environment
// variables, or remote configuration services.
type Loader interface {
	// Load retrieves and parses the configuration from the underlying source.
	// It returns the parsed configuration or an error if loading fails.
	Load(ctx context.Context) (*Config, error)
}

// FileLoader loads configuration from a file on disk. It implements the Loader
// interface to provide file-based configuration management.
type FileLoader struct {
	// path is the filesystem path to the configuration file.
	path string
}

// NewFileLoader creates a new FileLoader that will load configuration from the
// specified file path. This provides a simple way to initialize file-based
// configuration loading.
func NewFileLoader(path string) *FileLoader {
	return &FileLoader{path: path}
}

// Load reads and parses the configuration file specified in FileLoader.path.
// It returns the parsed configuration or an error if reading or parsing fails.
// The context parameter allows for cancellation of long-running operations.
func (l *FileLoader) Load(ctx context.Context) (*Config, error) {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &cfg, nil
}
