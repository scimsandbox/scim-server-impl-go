package configloader

import (
	"errors"
	"fmt"
	"os"
	"reflect"
)

type LookupEnvFunc func(string) (string, bool)

type LoadOptions struct {
	Files     []string
	EnvPrefix string
	LookupEnv LookupEnvFunc
}

func Load[T any](options LoadOptions) (T, error) {
	var cfg T
	return LoadWithDefaults(cfg, options)
}

func LoadWithDefaults[T any](defaults T, options LoadOptions) (T, error) {
	cfg := defaults

	typ := reflect.TypeOf(cfg)
	if typ == nil || typ.Kind() != reflect.Struct {
		var zero T
		return zero, errors.New("config type must be a struct")
	}
	if len(options.Files) == 0 {
		var zero T
		return zero, errors.New("at least one config file is required")
	}

	for _, path := range options.Files {
		contents, err := os.ReadFile(path)
		if err != nil {
			var zero T
			return zero, fmt.Errorf("read %s: %w", path, err)
		}
		if err := decodeMinimalYAML(contents, &cfg); err != nil {
			var zero T
			return zero, fmt.Errorf("load %s: %w", path, err)
		}
	}

	lookupEnv := options.LookupEnv
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	if err := applyEnvOverrides(reflect.ValueOf(&cfg), options.EnvPrefix, lookupEnv); err != nil {
		var zero T
		return zero, err
	}

	return cfg, nil
}
