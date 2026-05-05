package jsoncodec

import "io"

type JsonCodec struct {
	Marshal        func(v any) ([]byte, error)
	MarshalIndent  func(v any, prefix, indent string) ([]byte, error)
	Unmarshal      func(data []byte, v any) error
	NewJsonEncoder func(writer io.Writer) JsonEncoder
	NewJsonDecoder func(reader io.Reader) JsonDecoder
	Valid          func(data []byte) bool
}

type JsonEncoder interface {
	Encode(v any) error
	SetEscapeHTML(on bool)
	SetIndent(prefix, indent string)
}

type JsonDecoder interface {
	Decode(v any) error
	Buffered() io.Reader
	DisallowUnknownFields()
	More() bool
	UseNumber()
}
