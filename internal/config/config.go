package config

import "time"

// Registry represents a package registry type.
type Registry string

const (
	NPM  Registry = "npm"
	PyPI Registry = "pypi"
)

// Config holds all detonation parameters.
type Config struct {
	PackageName       string
	Registry          Registry
	DetonationTimeout time.Duration
	NPMImage          string
	PyPIImage         string
	MemoryLimitMB     int64
	PidsLimit         int64
	KafkaBroker       string
	KafkaTopic        string
	LocalPackage      string // Path to a local .tgz package to detonate
	AllowNetwork      bool   // Allow network access for npm install (required for registry packages)
	Lockfile          string
	Limit             int
}

// DefaultConfig returns sane defaults for a detonation run.
func DefaultConfig() *Config {
	return &Config{
		Registry:          NPM,
		DetonationTimeout: 30 * time.Second,
		NPMImage:          "node:22-alpine",
		PyPIImage:         "python:3.12-alpine",
		MemoryLimitMB:     256,
		PidsLimit:         100,
		KafkaBroker:       "localhost:9092",
		KafkaTopic:        "syscall-telemetry",
	}
}

// Image returns the container image for the configured registry.
func (c *Config) Image() string {
	if c.Registry == PyPI {
		return c.PyPIImage
	}
	return c.NPMImage
}

// InstallCommand returns the package install command for the configured registry.
func (c *Config) InstallCommand() string {
	if c.LocalPackage != "" {
		return "npm install /pkg/package.tgz"
	}
	switch c.Registry {
	case PyPI:
		return "pip install " + c.PackageName
	default:
		return "npm install " + c.PackageName
	}
}
