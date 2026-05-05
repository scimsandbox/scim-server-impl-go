package jsoncodec

import (
	"io"

	gojson "github.com/goccy/go-json"
)

var defaultJsonCodec = JsonCodec{
	Marshal:       gojson.Marshal,
	MarshalIndent: gojson.MarshalIndent,
	Unmarshal:     gojson.Unmarshal,
	NewJsonEncoder: func(writer io.Writer) JsonEncoder {
		return gojson.NewEncoder(writer)
	},
	NewJsonDecoder: func(reader io.Reader) JsonDecoder {
		return gojson.NewDecoder(reader)
	},
	Valid: gojson.Valid,
}

func NewJsonCodec() JsonCodec {
	return defaultJsonCodec
}
