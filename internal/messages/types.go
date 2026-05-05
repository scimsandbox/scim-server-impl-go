package messages

type Language string

const (
	English Language = "en"
	Spanish Language = "es"
)

type Key string

const (
	KeyStdoutWriterRequired        Key = "error.stdout_writer_required"
	KeyConfigFileNotFound          Key = "error.config_file_not_found"
	KeyConfigFileStat              Key = "error.config_file_stat"
	KeyRequiredConfigValueStillSet Key = "error.required_config_value_still_set"
	KeyAPIBearerTokenRequired      Key = "error.api_bearer_token_required"
	KeyAPIBodyRequired             Key = "error.api_body_required"
	KeyAPIInvalidJSON              Key = "error.api_invalid_json"
	KeyAPIRequestTooLarge          Key = "error.api_request_too_large"
	KeyConfigurationLoaded         Key = "log.configuration_loaded"
	KeyConfigurationRendered       Key = "log.configuration_rendered"
	KeyHTTPServerStarted           Key = "log.http_server_started"
	KeyHTTPServerStopped           Key = "log.http_server_stopped"
	KeyHTTPRequestCompleted        Key = "log.http_request_completed"
)

type Config struct {
	Language Language `yaml:"language" env:"GO_MESSAGES_LANGUAGE"`
}

type Localizer interface {
	Language() Language
	Template(key Key) string
	Text(key Key, args ...any) string
	WithLanguage(language Language) Localizer
}
