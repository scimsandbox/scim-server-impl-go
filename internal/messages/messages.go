package messages

func New(config Config) Localizer {
	return embeddedLocalizer{language: resolveLanguage(config.Language)}
}
