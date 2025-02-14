// Package config provides serialization functions for configuration-related types
package config

import (
	"fmt"
	"time"

	"github.com/ahrav/gitleaks-armada/internal/config"
	serializationerrors "github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/errors"
	"github.com/ahrav/gitleaks-armada/internal/infra/eventbus/serialization/protobuf/shared"
	pb "github.com/ahrav/gitleaks-armada/proto"
)

// ConfigToProto converts a domain config to its protobuf representation.
func ConfigToProto(cfg *config.Config) (*pb.ScanConfig, error) {
	if cfg == nil {
		return nil, serializationerrors.ErrNilEvent{EventType: "Config"}
	}

	pbCfg := &pb.ScanConfig{
		Auth:    make(map[string]*pb.AuthConfig),
		Targets: make([]*pb.TargetSpec, 0, len(cfg.Targets)),
	}

	// Convert auth configs.
	for k, v := range cfg.Auth {
		// Convert map[string]any to map[string]string.
		stringConfig := make(map[string]string)
		for configKey, configVal := range v.Config {
			stringConfig[configKey] = fmt.Sprintf("%v", configVal)
		}

		pbCfg.Auth[k] = &pb.AuthConfig{
			Type:   v.Type,
			Config: stringConfig,
		}
	}

	for _, t := range cfg.Targets {
		target, err := targetSpecToProto(&t)
		if err != nil {
			return nil, fmt.Errorf("convert target spec: %w", err)
		}
		pbCfg.Targets = append(pbCfg.Targets, target)
	}

	return pbCfg, nil
}

// ProtoToConfig converts a protobuf config to its domain representation.
func ProtoToConfig(pbCfg *pb.ScanConfig) (*config.Config, error) {
	if pbCfg == nil {
		return nil, serializationerrors.ErrNilEvent{EventType: "Config"}
	}

	cfg := &config.Config{
		Auth:    make(map[string]config.AuthConfig),
		Targets: make([]config.TargetSpec, 0, len(pbCfg.Targets)),
	}

	// Convert auth configs.
	for k, v := range pbCfg.Auth {
		// Convert map[string]string to map[string]any.
		anyConfig := make(map[string]any)
		for configKey, configVal := range v.Config {
			anyConfig[configKey] = configVal
		}

		cfg.Auth[k] = config.AuthConfig{
			Type:   v.Type,
			Config: anyConfig,
		}
	}

	for _, t := range pbCfg.Targets {
		target, err := protoToTargetSpec(t)
		if err != nil {
			return nil, fmt.Errorf("convert target spec: %w", err)
		}
		cfg.Targets = append(cfg.Targets, target)
	}

	return cfg, nil
}

// targetSpecToProto converts a config.TargetSpec to its protobuf representation.
func targetSpecToProto(spec *config.TargetSpec) (*pb.TargetSpec, error) {
	if spec == nil {
		return nil, serializationerrors.ErrNilEvent{EventType: "TargetSpec"}
	}

	sourceType, err := shared.SourceTypeToProto(spec.SourceType)
	if err != nil {
		return nil, fmt.Errorf("convert source type: %w", err)
	}

	pbSpec := &pb.TargetSpec{
		Name:       spec.Name,
		SourceType: sourceType,
		AuthRef:    spec.AuthRef,
	}

	switch {
	case spec.GitHub != nil:
		pbSpec.Target = &pb.TargetSpec_Github{
			Github: &pb.GitHubTarget{
				Org:      spec.GitHub.Org,
				RepoList: spec.GitHub.RepoList,
				Metadata: spec.GitHub.Metadata,
			},
		}
	case spec.S3 != nil:
		pbSpec.Target = &pb.TargetSpec_S3{
			S3: &pb.S3Target{
				Bucket:   spec.S3.Bucket,
				Prefix:   spec.S3.Prefix,
				Region:   spec.S3.Region,
				Metadata: spec.S3.Metadata,
			},
		}
	case spec.URL != nil:
		retry := &pb.RetryConfig{
			MaxAttempts:   int32(spec.URL.RetryConfig.MaxAttempts),
			InitialWaitMs: spec.URL.RetryConfig.InitialWait.Milliseconds(),
			MaxWaitMs:     spec.URL.RetryConfig.MaxWait.Milliseconds(),
		}
		pbSpec.Target = &pb.TargetSpec_Url{
			Url: &pb.URLTarget{
				Urls:          spec.URL.URLs,
				ArchiveFormat: string(spec.URL.ArchiveFormat),
				Headers:       spec.URL.Headers,
				RateLimit:     spec.URL.RateLimit,
				Retry:         retry,
				Metadata:      spec.URL.Metadata,
			},
		}
	}

	return pbSpec, nil
}

// protoToTargetSpec converts a protobuf TargetSpec to its domain representation.
func protoToTargetSpec(pbSpec *pb.TargetSpec) (config.TargetSpec, error) {
	if pbSpec == nil {
		return config.TargetSpec{}, serializationerrors.ErrNilEvent{EventType: "TargetSpec"}
	}

	sourceType, err := shared.ProtoToSourceType(pbSpec.SourceType)
	if err != nil {
		return config.TargetSpec{}, fmt.Errorf("convert source type: %w", err)
	}

	spec := config.TargetSpec{
		Name:       pbSpec.Name,
		SourceType: sourceType,
		AuthRef:    pbSpec.AuthRef,
	}

	switch t := pbSpec.Target.(type) {
	case *pb.TargetSpec_Github:
		spec.GitHub = &config.GitHubTarget{
			Org:      t.Github.Org,
			RepoList: t.Github.RepoList,
			Metadata: t.Github.Metadata,
		}
	case *pb.TargetSpec_S3:
		spec.S3 = &config.S3Target{
			Bucket:   t.S3.Bucket,
			Prefix:   t.S3.Prefix,
			Region:   t.S3.Region,
			Metadata: t.S3.Metadata,
		}
	case *pb.TargetSpec_Url:
		spec.URL = &config.URLTarget{
			URLs:          t.Url.Urls,
			ArchiveFormat: config.ArchiveFormat(t.Url.ArchiveFormat),
			Headers:       t.Url.Headers,
			RateLimit:     t.Url.RateLimit,
			Metadata:      t.Url.Metadata,
		}
		if t.Url.Retry != nil {
			spec.URL.RetryConfig = &config.RetryConfig{
				MaxAttempts: int(t.Url.Retry.MaxAttempts),
				InitialWait: time.Duration(t.Url.Retry.InitialWaitMs) * time.Millisecond,
				MaxWait:     time.Duration(t.Url.Retry.MaxWaitMs) * time.Millisecond,
			}
		}
	}

	return spec, nil
}
