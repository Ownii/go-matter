package tlv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

func Decode(tlv Element, out interface{}) error {
	rv := reflect.ValueOf(out)
	if rv.Kind() != reflect.Ptr {
		return errors.New("out must be a pointer")
	}

	elem := rv.Elem()

	if elem.Type() == reflect.TypeOf(Element{}) {
		elem.Set(reflect.ValueOf(tlv))
		return nil
	}

	switch elem.Kind() {
	case reflect.Ptr:
		if tlv.Type == TypeNull {
			elem.Set(reflect.Zero(elem.Type()))
			return nil
		}
		if elem.IsNil() {
			elem.Set(reflect.New(elem.Type().Elem()))
		}
		return Decode(tlv, elem.Interface())
	case reflect.Bool:
		return decodeBool(tlv, elem)
	case reflect.String:
		return decodeString(tlv, elem)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return decodeInt(tlv, elem)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return decodeUint(tlv, elem)
	case reflect.Slice:
		if elem.Type().Elem().Kind() == reflect.Uint8 {
			return decodeBytes(tlv, elem)
		}
		return decodeSlice(tlv, elem)
	case reflect.Struct:
		return decodeStruct(tlv, elem)
	}

	return nil
}

func decodeBool(tlv Element, elem reflect.Value) error {
	// Boolean True is 0x09, False is 0x08.
	if tlv.Type != TypeBoolean && tlv.Type != TypeBoolean+1 {
		return fmt.Errorf("expected boolean type, got %x", tlv.Type)
	}
	// Boolean True is 0x09, False is 0x08.
	// tlv.Type == TypeBoolean (0x08) -> False
	// tlv.Type == TypeBoolean+1 (0x09) -> True
	// Note: Reader might put simple []byte{0} or []byte{1} in Value, need to align with Reader.
	// Re-checking Reader:
	// case elemType == TypeBoolean: return []byte{0}, nil
	// case elemType == TypeBoolean+1: return []byte{1}, nil
	if len(tlv.Value) > 0 && tlv.Value[0] == 1 {
		elem.SetBool(true)
	} else {
		elem.SetBool(false)
	}
	return nil
}

func decodeString(tlv Element, elem reflect.Value) error {
	// TODO: handle byte string vs utf8 distinction if needed
	// Masking to check base type
	if (tlv.Type & 0xFC) != TypeUTF8String {
		return fmt.Errorf("expected string type, got %x", tlv.Type)
	}
	elem.SetString(string(tlv.Value))
	return nil
}

func decodeBytes(tlv Element, elem reflect.Value) error {
	if (tlv.Type & 0xFC) != TypeByteString {
		return fmt.Errorf("expected byte string type, got %x", tlv.Type)
	}
	elem.SetBytes(tlv.Value)
	return nil
}

func decodeInt(tlv Element, elem reflect.Value) error {
	// Signed Int Types: 0x00, 0x01, 0x02, 0x03
	if (tlv.Type & 0xFC) != TypeSignedInt {
		return fmt.Errorf("expected signed int type, got %x", tlv.Type)
	}

	val, err := parseSignedInt(tlv.Value)
	if err != nil {
		return err
	}
	if elem.OverflowInt(val) {
		return fmt.Errorf("value %d changes overflow type %s", val, elem.Type())
	}
	elem.SetInt(val)
	return nil
}

func decodeUint(tlv Element, elem reflect.Value) error {
	// Unsigned Int Types: 0x04, 0x05, 0x06, 0x07
	if (tlv.Type & 0xFC) != TypeUnsignedInt {
		return fmt.Errorf("expected unsigned int type, got %x", tlv.Type)
	}

	val, err := parseUnsignedInt(tlv.Value)
	if err != nil {
		return err
	}
	if elem.OverflowUint(val) {
		return fmt.Errorf("value %d overflows type %s", val, elem.Type())
	}
	elem.SetUint(val)
	return nil
}

func parseSignedInt(b []byte) (int64, error) {
	switch len(b) {
	case 1:
		return int64(int8(b[0])), nil
	case 2:
		return int64(int16(binary.LittleEndian.Uint16(b))), nil
	case 4:
		return int64(int32(binary.LittleEndian.Uint32(b))), nil
	case 8:
		return int64(binary.LittleEndian.Uint64(b)), nil
	default:
		return 0, fmt.Errorf("invalid integer length: %d", len(b))
	}
}

func parseUnsignedInt(b []byte) (uint64, error) {
	switch len(b) {
	case 1:
		return uint64(b[0]), nil
	case 2:
		return uint64(binary.LittleEndian.Uint16(b)), nil
	case 4:
		return uint64(binary.LittleEndian.Uint32(b)), nil
	case 8:
		return binary.LittleEndian.Uint64(b), nil
	default:
		return 0, fmt.Errorf("invalid integer length: %d", len(b))
	}
}

func decodeSlice(tlv Element, elem reflect.Value) error {
	// TODO: Update logic to use SubElements now that they exist
	if tlv.Type != TypeArray && tlv.Type != TypeList {
		return fmt.Errorf("expected Array or List, got %x", tlv.Type)
	}

	for _, child := range tlv.SubElements {
		newElem := reflect.New(elem.Type().Elem()).Elem()
		err := Decode(child, newElem.Addr().Interface())
		if err != nil {
			return err
		}
		elem.Set(reflect.Append(elem, newElem))
	}
	return nil
}

func decodeStruct(tlv Element, elem reflect.Value) error {
	if tlv.Type != TypeStructure {
		return fmt.Errorf("expected structure, got %x", tlv.Type)
	}

	for i := 0; i < elem.NumField(); i++ {
		field := elem.Type().Field(i)
		tagStr := field.Tag.Get("tlv")
		tags := strings.Split(tagStr, ",")
		if len(tags) == 0 || tags[0] == "" || tags[0] == "-1" || !field.IsExported() {
			continue
		}
		tagID, err := strconv.Atoi(tags[0])
		if err != nil {
			return fmt.Errorf("invalid tlv-Tag: %s, expected integer", tags[0])
		}

		// Find child with matching tag
		// Assuming ContextSpecific tags for struct fields for now (Class 0x20)
		// Or simpler: just match ID?
		var item *Element
		for _, child := range tlv.SubElements {
			if child.Tag.ID == uint64(tagID) {
				// Potential check for Tag.Class == ContextSpecific
				item = &child
				break
			}
		}

		if item == nil {
			continue
		}
		err = Decode(*item, elem.Field(i).Addr().Interface())
		if err != nil {
			return err
		}
	}
	return nil
}

// checkType is deprecated/replaced by direct checks in decoders
func checkType(tlv Element, expectedType ElementType) (bool, error) {
	if tlv.Type == TypeNull {
		return false, nil
	}
	// Simple equality check is insufficient for types with length bits
	if tlv.Type != expectedType {
		return false, fmt.Errorf("TLV item is not of expected type %d, got %d", expectedType, tlv.Type)
	}
	return true, nil
}
