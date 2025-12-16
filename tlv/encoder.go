package tlv

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
)

// Encoder encodes Go values into Matter TLV format.
type Encoder struct {
	w *Writer
}

// NewEncoder creates a new TLV encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w: NewWriter(w)}
}

// Encode writes the TLV encoding of v to the stream.
func (e *Encoder) Encode(v interface{}) error {
	// Root element is usually anonymous, unless specified otherwise.
	// We'll treat the top-level call as anonymous.
	return e.encodeValue(reflect.ValueOf(v), Tag{Class: TagControlAnonymous})
}

// Marshal is a helper that returns the TLV bytes for v.
func Marshal(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (e *Encoder) encodeValue(v reflect.Value, tag Tag) error {
	// Handle pointers by dereferencing
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			// Write Null? Or just return?
			// Matter often omits optional fields if nil.
			// But if explicitly encoding a nil pointer as a value, maybe Null is appropriate.
			// For now, let's write Null.
			// TODO: Check if omitting is better for struct fields.
			// The struct walker below handles omission. Here we are encoding a specific value.
			// Writing Null seems safest for explicit encode calls.
			return e.w.writeControlByte(tag.Class, TypeNull) // Simplified null writing
		}
		return e.encodeValue(v.Elem(), tag)
	}

	if v.Kind() == reflect.Interface {
		if v.IsNil() {
			return e.w.writeControlByte(tag.Class, TypeNull)
		}
		return e.encodeValue(v.Elem(), tag)
	}

	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// PutSignedInt automatically picks the smallest length
		return e.w.PutSignedInt(tag, v.Int())

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return e.w.PutUnsignedInt(tag, v.Uint())

	case reflect.Bool:
		return e.w.PutBoolean(tag, v.Bool())

	case reflect.String:
		return e.w.PutString(tag, v.String())

	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			// Byte Slice -> Byte String
			return e.w.PutBytes(tag, v.Bytes())
		}
		// Generic Slice -> Array (or List, logic can be ambiguous, default to Array)
		return e.encodeContainer(v, tag, TypeArray)

	case reflect.Struct:
		return e.encodeStruct(v, tag)

	default:
		return fmt.Errorf("unsupported type: %v", v.Kind())
	}
}

func (e *Encoder) encodeContainer(v reflect.Value, tag Tag, containerType ElementType) error {
	if err := e.w.StartContainer(tag, containerType); err != nil {
		return err
	}
	for i := 0; i < v.Len(); i++ {
		// Element tags in arrays are Anonymous
		if err := e.encodeValue(v.Index(i), Tag{Class: TagControlAnonymous}); err != nil {
			return err
		}
	}
	return e.w.EndContainer()
}

func (e *Encoder) encodeStruct(v reflect.Value, tag Tag) error {
	if err := e.w.StartContainer(tag, TypeStructure); err != nil {
		return err
	}

	for i := 0; i < v.NumField(); i++ {
		fieldInfo := v.Type().Field(i)
		tlvTag := fieldInfo.Tag.Get("tlv")
		if tlvTag == "" || tlvTag == "-" {
			continue // Skip fields without tlv tag
		}

		tags := strings.Split(tlvTag, ",")
		tagIDStr := tags[0]

		// Parse options
		omitEmpty := false
		for _, t := range tags[1:] {
			if t == "omitempty" {
				omitEmpty = true
			}
		}

		if omitEmpty && isEmptyValue(v.Field(i)) {
			continue
		}

		tagID, err := strconv.ParseUint(tagIDStr, 10, 8)
		if err != nil {
			return fmt.Errorf("invalid tlv tag ID on field %s: %s", fieldInfo.Name, tagIDStr)
		}

		// Assume ContextSpecific tags for struct fields
		fieldTag := Tag{Class: TagControlContextSpecific, ID: tagID}

		if err := e.encodeValue(v.Field(i), fieldTag); err != nil {
			return err
		}
	}

	return e.w.EndContainer()
}

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return false
}
