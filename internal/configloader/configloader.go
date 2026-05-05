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

	typ := reflect.TypeOf(cfg)
	if typ == nil || typ.Kind() != reflect.Struct {
		return cfg, errors.New("config type must be a struct")
	}
	if len(options.Files) == 0 {
		return cfg, errors.New("at least one config file is required")
	}

	for _, path := range options.Files {
		contents, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read %s: %w", path, err)
		}
		if err := decodeMinimalYAML(contents, &cfg); err != nil {
			return cfg, fmt.Errorf("load %s: %w", path, err)
		}
	}

	lookupEnv := options.LookupEnv
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	if err := applyEnvOverrides(reflect.ValueOf(&cfg), options.EnvPrefix, lookupEnv); err != nil {
		return cfg, err
	}

	return cfg, nil
}
