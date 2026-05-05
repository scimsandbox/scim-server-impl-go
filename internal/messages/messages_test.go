package messages

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	wantLanguageFmt          = "Language() = %q, want %q"
	wantLocalizedSpanishText = "Text() = %q, want localized Spanish text"
)

func TestNewDefaultsToEnglish(t *testing.T) {
	t.Parallel()

	localizer := New(Config{})
	if got := localizer.Language(); got != English {
		t.Fatalf(wantLanguageFmt, got, English)
	}
	if got := localizer.Text(KeyConfigurationLoaded); got != "configuration loaded" {
		t.Fatalf("Text() = %q, want configuration loaded", got)
	}
}

func TestNewUsesSpanishBundle(t *testing.T) {
	t.Parallel()

	localizer := New(Config{Language: Spanish})
	if got := localizer.Language(); got != Spanish {
		t.Fatalf(wantLanguageFmt, got, Spanish)
	}
	if got := localizer.Text(KeyConfigurationLoaded); got != "configuración cargada" {
		t.Fatalf(wantLocalizedSpanishText, got)
	}
	if got := localizer.Text(KeyStdoutWriterRequired); got != "se requiere un escritor para stdout" {
		t.Fatalf(wantLocalizedSpanishText, got)
	}
}

func TestUnsupportedLanguageFallsBackToEnglish(t *testing.T) {
	t.Parallel()

	localizer := New(Config{Language: Language("de-DE")})
	if got := localizer.Language(); got != English {
		t.Fatalf(wantLanguageFmt, got, English)
	}
	if got := localizer.Text(KeyConfigurationRendered); got != "configuration rendered" {
		t.Fatalf("Text() = %q, want configuration rendered", got)
	}
}

func TestTextSupportsWrappedErrors(t *testing.T) {
	t.Parallel()

	localizer := New(Config{Language: Spanish})
	cause := errors.New("boom")
	err := fmt.Errorf("%s: %w", localizer.Text(KeyConfigFileStat, "config/app-conf.yaml"), cause)
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is(err, cause) = false, want true")
	}
	if got := err.Error(); !strings.Contains(got, "config/app-conf.yaml") || !strings.Contains(got, "boom") {
		t.Fatalf("Error() = %q, want wrapped file path and cause", got)
	}
}

func TestTemplateReturnsLocalizedFormatString(t *testing.T) {
	t.Parallel()

	localizer := New(Config{Language: Spanish})
	if got := localizer.Template(KeyConfigFileStat); got != "error al consultar %s" {
		t.Fatalf("Template() = %q, want localized format string", got)
	}
}

func TestWithLanguageSwitchesLanguage(t *testing.T) {
	t.Parallel()

	english := New(Config{})
	spanish := english.WithLanguage(Spanish)

	if got := spanish.Language(); got != Spanish {
		t.Fatalf(wantLanguageFmt, got, Spanish)
	}
	if got := spanish.Text(KeyConfigurationLoaded); got != "configuración cargada" {
		t.Fatalf(wantLocalizedSpanishText, got)
	}
}
