package configloader

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

var durationType = reflect.TypeOf(time.Duration(0))

const (
	errAnchorsNotSupported   = "YAML anchors are not supported"
	errAliasesNotSupported   = "YAML aliases are not supported"
	errMapKeysMustBeScalars  = "YAML map keys must be scalars"
	errMergeKeysNotSupported = "YAML merge keys are not supported"
	errSequencesUnsupported  = "YAML sequences are not supported"
)

func decodeMinimalYAML(data []byte, target any) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil
	}
	if err := validateMinimalYAML(trimmed); err != nil {
		return err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(trimmed))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("multiple YAML documents are not supported")
	}

	return nil
}

func validateMinimalYAML(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	documentCount := 0

	for {
		var node yaml.Node
		if err := decoder.Decode(&node); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if len(node.Content) == 0 {
			continue
		}

		documentCount++
		if documentCount > 1 {
			return errors.New("multiple YAML documents are not supported")
		}
		if err := validateDocumentNode(node.Content[0]); err != nil {
			return err
		}
	}

	return nil
}

func validateDocumentNode(node *yaml.Node) error {
	if err := rejectAnchor(node); err != nil {
		return err
	}

	switch node.Kind {
	case yaml.MappingNode:
		return validateMappingNode(node)
	case yaml.SequenceNode:
		return errors.New(errSequencesUnsupported)
	default:
		return errors.New("YAML root node must be a mapping")
	}
}

func validateValueNode(node *yaml.Node) error {
	if err := rejectAnchor(node); err != nil {
		return err
	}

	switch node.Kind {
	case yaml.MappingNode:
		return validateMappingNode(node)
	case yaml.ScalarNode:
		return nil
	case yaml.SequenceNode:
		return errors.New(errSequencesUnsupported)
	case yaml.AliasNode:
		return errors.New(errAliasesNotSupported)
	default:
		return fmt.Errorf("unsupported YAML node kind %d", node.Kind)
	}
}

func validateMappingNode(node *yaml.Node) error {
	for index := 0; index < len(node.Content); index += 2 {
		keyNode := node.Content[index]
		valueNode := node.Content[index+1]

		if err := validateKeyNode(keyNode); err != nil {
			return err
		}
		if err := validateValueNode(valueNode); err != nil {
			return err
		}
	}

	return nil
}

func validateKeyNode(node *yaml.Node) error {
	if err := rejectAnchor(node); err != nil {
		return err
	}
	if node.Kind != yaml.ScalarNode {
		return errors.New(errMapKeysMustBeScalars)
	}
	if node.Value == "<<" {
		return errors.New(errMergeKeysNotSupported)
	}
	return nil
}

func rejectAnchor(node *yaml.Node) error {
	if node.Anchor != "" {
		return errors.New(errAnchorsNotSupported)
	}
	return nil
}

func applyEnvOverrides(root reflect.Value, prefix string, lookupEnv LookupEnvFunc) error {
	if root.Kind() != reflect.Pointer || root.IsNil() {
		return errors.New("config target must be a non-nil pointer")
	}
	value := root.Elem()
	if value.Kind() != reflect.Struct {
		return errors.New("config target must point to a struct")
	}

	return walkStruct(value, prefix, nil, lookupEnv)
}

func walkStruct(value reflect.Value, prefix string, path []string, lookupEnv LookupEnvFunc) error {
	typ := value.Type()
	for index := 0; index < value.NumField(); index++ {
		fieldType := typ.Field(index)
		if !fieldType.IsExported() {
			continue
		}

		name := yamlFieldName(fieldType)
		if name == "" {
			continue
		}

		fieldValue := value.Field(index)
		currentPath := appendPath(path, name)

		if fieldValue.Kind() == reflect.Struct && fieldValue.Type() != durationType {
			if err := walkStruct(fieldValue, prefix, currentPath, lookupEnv); err != nil {
				return err
			}
			continue
		}

		envName := envName(fieldType, prefix, currentPath)
		raw, ok := lookupEnv(envName)
		if !ok {
			continue
		}
		if err := setValue(fieldValue, raw); err != nil {
			return fmt.Errorf("apply %s: %w", envName, err)
		}
	}

	return nil
}

func appendPath(path []string, element string) []string {
	result := make([]string, len(path)+1)
	copy(result, path)
	result[len(path)] = element
	return result
}

func yamlFieldName(field reflect.StructField) string {
	tag := field.Tag.Get("yaml")
	if tag == "-" {
		return ""
	}
	if tag != "" {
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			return toSnakeCase(field.Name)
		}
		return name
	}
	return toSnakeCase(field.Name)
}

func envName(field reflect.StructField, prefix string, path []string) string {
	if override := field.Tag.Get("env"); override != "" {
		return override
	}

	parts := make([]string, 0, len(path)+1)
	if prefix != "" {
		parts = append(parts, strings.TrimSuffix(prefix, "_"))
	}
	for _, part := range path {
		parts = append(parts, normalizeEnvPart(part))
	}
	return strings.Join(parts, "_")
}

func normalizeEnvPart(input string) string {
	var builder strings.Builder
	for _, r := range input {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			builder.WriteRune(unicode.ToUpper(r))
		default:
			builder.WriteByte('_')
		}
	}
	return strings.Trim(builder.String(), "_")
}

func toSnakeCase(input string) string {
	if input == "" {
		return ""
	}

	var builder strings.Builder
	for index, r := range input {
		if unicode.IsUpper(r) {
			if index > 0 {
				builder.WriteByte('_')
			}
			builder.WriteRune(unicode.ToLower(r))
			continue
		}
		builder.WriteRune(r)
	}

	return builder.String()
}

func setValue(field reflect.Value, raw string) error {
	if !field.CanSet() {
		return errors.New("field cannot be set")
	}

	typ := field.Type()
	if typ == durationType {
		value, err := time.ParseDuration(raw)
		if err != nil {
			return err
		}
		field.SetInt(int64(value))
		return nil
	}

	switch field.Kind() {
	case reflect.String:
		field.SetString(raw)
		return nil
	case reflect.Bool:
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return err
		}
		field.SetBool(value)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value, err := strconv.ParseInt(raw, 10, typ.Bits())
		if err != nil {
			return err
		}
		field.SetInt(value)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value, err := strconv.ParseUint(raw, 10, typ.Bits())
		if err != nil {
			return err
		}
		field.SetUint(value)
		return nil
	case reflect.Float32, reflect.Float64:
		value, err := strconv.ParseFloat(raw, typ.Bits())
		if err != nil {
			return err
		}
		field.SetFloat(value)
		return nil
	default:
		return fmt.Errorf("unsupported field type %s", typ)
	}
}
