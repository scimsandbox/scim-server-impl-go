package messages

import (
	"embed"
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

//go:embed locales/*.json
var bundleFS embed.FS

type embeddedLocalizer struct {
	language Language
}

var bundles = mustLoadBundles()

func (l embeddedLocalizer) Language() Language {
	return l.language
}

func (l embeddedLocalizer) Template(key Key) string {
	if template, ok := localizedTemplate(l.language, key); ok {
		return template
	}
	return string(key)
}

func (l embeddedLocalizer) Text(key Key, args ...any) string {
	return fmt.Sprintf(l.Template(key), args...)
}

func (l embeddedLocalizer) WithLanguage(language Language) Localizer {
	return embeddedLocalizer{language: resolveLanguage(language)}
}

func localizedTemplate(language Language, key Key) (string, bool) {
	if templates, ok := bundles[language]; ok {
		if template, ok := templates[key]; ok {
			return template, true
		}
	}
	if language != English {
		if templates, ok := bundles[English]; ok {
			if template, ok := templates[key]; ok {
				return template, true
			}
		}
	}
	return "", false
}

func resolveLanguage(language Language) Language {
	normalized := normalizeLanguage(language)
	if normalized == English {
		return English
	}
	if _, ok := bundles[normalized]; ok {
		return normalized
	}
	return English
}

func normalizeLanguage(language Language) Language {
	value := strings.ToLower(strings.TrimSpace(string(language)))
	if value == "" {
		return English
	}
	value = strings.ReplaceAll(value, "_", "-")
	if base, _, ok := strings.Cut(value, "-"); ok {
		value = base
	}
	return Language(value)
}

func mustLoadBundles() map[Language]map[Key]string {
	entries, err := bundleFS.ReadDir("locales")
	if err != nil {
		panic(fmt.Errorf("read embedded message bundles: %w", err))
	}

	loaded := make(map[Language]map[Key]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), path.Ext(entry.Name()))
		data, err := bundleFS.ReadFile(path.Join("locales", entry.Name()))
		if err != nil {
			panic(fmt.Errorf("read embedded message bundle %s: %w", entry.Name(), err))
		}

		var raw map[string]string
		if err := json.Unmarshal(data, &raw); err != nil {
			panic(fmt.Errorf("decode embedded message bundle %s: %w", entry.Name(), err))
		}

		bundle := make(map[Key]string, len(raw))
		for key, value := range raw {
			bundle[Key(key)] = value
		}
		loaded[normalizeLanguage(Language(name))] = bundle
	}

	if _, ok := loaded[English]; !ok {
		panic("embedded English message bundle is required")
	}

	return loaded
}
