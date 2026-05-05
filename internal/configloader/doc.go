// Package configloader provides a generic, layered YAML configuration loader
// with environment variable overrides.
//
// Usage:
//
//	cfg, err := configloader.Load[AppConfig](configloader.LoadOptions{
//	    Files:     []string{"config/app-conf.yaml", "config/app-secrets.yaml"},
//	    EnvPrefix: "APP_",
//	})
//
// Files are merged in order (later files override earlier ones). Environment
// variables override file-loaded values. YAML sequences, anchors, aliases, and
// merge keys are intentionally rejected to keep configurations simple and
// auditable.
package configloader
