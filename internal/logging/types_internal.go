package logging

type fieldKind uint8

const (
	fieldUnset fieldKind = iota
	fieldAny
	fieldString
	fieldInt
	fieldInt64
	fieldUint64
	fieldBool
	fieldDuration
	fieldTime
	fieldStrings
	fieldStringer
	fieldError
	fieldFloat64
)
