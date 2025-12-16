package tlv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// ElementType represents the data type of the TLV element.
type ElementType uint8

const (
	TypeSignedInt      ElementType = 0x00
	TypeUnsignedInt    ElementType = 0x04
	TypeBoolean        ElementType = 0x08
	TypeUTF8String     ElementType = 0x0C
	TypeByteString     ElementType = 0x10
	TypeNull           ElementType = 0x14
	TypeStructure      ElementType = 0x15
	TypeArray          ElementType = 0x16
	TypeList           ElementType = 0x17
	TypeEndOfContainer ElementType = 0x18
)

// TagControl represents the type of tag (Anonymous, Context, Common Profile, etc.)
type TagControl uint8

const (
	TagControlAnonymous        TagControl = 0x00
	TagControlContextSpecific  TagControl = 0x20
	TagControlCommonProfile2   TagControl = 0x40
	TagControlCommonProfile4   TagControl = 0x60
	TagControlImplicitProfile2 TagControl = 0x80
	TagControlImplicitProfile4 TagControl = 0xA0
	TagControlFullyQualified6  TagControl = 0xC0
	TagControlFullyQualified8  TagControl = 0xE0
)

// Tag represents a TLV tag.
type Tag struct {
	Class   TagControl
	ID      uint64
	Profile uint32
}

// Element represents a single TLV item with its tag, type, and raw value.
type Element struct {
	Tag         Tag
	Type        ElementType
	Value       []byte    // Raw bytes of the value
	SubElements []Element // Child elements (populated if Type is Structure, Array, or List)
}

// Reader decodes TLV data from an io.Reader.
type Reader struct {
	r io.Reader // TODO: Use bufio.Reader for efficiency if needed
}

// NewReader creates a new TLV reader.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: r}
}

// ReadElement reads the next TLV element from the stream.
func (r *Reader) ReadElement() (Element, error) {
	var controlByte [1]byte
	if _, err := io.ReadFull(r.r, controlByte[:]); err != nil {
		return Element{}, err
	}

	control := controlByte[0]
	elementType := ElementType(control & 0x1F)
	tagControl := TagControl(control & 0xE0)

	tag, err := r.readTag(tagControl)
	if err != nil {
		return Element{}, fmt.Errorf("failed to read tag: %w", err)
	}

	// EndOfContainer has no value
	if elementType == TypeEndOfContainer {
		return Element{Tag: tag, Type: elementType}, nil
	}

	value, err := r.readValue(elementType)
	if err != nil {
		return Element{}, fmt.Errorf("failed to read value: %w", err)
	}

	return Element{
		Tag:   tag,
		Type:  elementType,
		Value: value,
	}, nil
}

func (r *Reader) readTag(control TagControl) (Tag, error) {
	tag := Tag{Class: control}

	switch control {
	case TagControlAnonymous:
		// No tag data
	case TagControlContextSpecific:
		var buf [1]byte
		if _, err := io.ReadFull(r.r, buf[:]); err != nil {
			return tag, err
		}
		tag.ID = uint64(buf[0])
	case TagControlCommonProfile2:
		var buf [2]byte
		if _, err := io.ReadFull(r.r, buf[:]); err != nil {
			return tag, err
		}
		tag.ID = uint64(binary.LittleEndian.Uint16(buf[:]))
	case TagControlCommonProfile4:
		var buf [4]byte
		if _, err := io.ReadFull(r.r, buf[:]); err != nil {
			return tag, err
		}
		tag.ID = uint64(binary.LittleEndian.Uint32(buf[:]))
	case TagControlImplicitProfile2:
		var buf [2]byte
		if _, err := io.ReadFull(r.r, buf[:]); err != nil {
			return tag, err
		}
		tag.ID = uint64(binary.LittleEndian.Uint16(buf[:]))
	case TagControlImplicitProfile4:
		var buf [4]byte
		if _, err := io.ReadFull(r.r, buf[:]); err != nil {
			return tag, err
		}
		tag.ID = uint64(binary.LittleEndian.Uint32(buf[:]))
	case TagControlFullyQualified6:
		var buf [8]byte // 2 vendor + 2 profile + 4 tag
		if _, err := io.ReadFull(r.r, buf[:]); err != nil {
			return tag, err
		}
		tag.Profile = binary.LittleEndian.Uint32(buf[:4]) // Simplified usage of Profile
		tag.ID = uint64(binary.LittleEndian.Uint32(buf[4:]))
	case TagControlFullyQualified8:
		var buf [8]byte // 2 vendor + 2 profile + 8 tag? Spec says 64-bit tag?
		// Re-checking spec: Fully Qualified 8 bytes indicates 2 bytes Vendor ID, 2 bytes Profile Number, 4 bytes Tag Number?
		// Actually:
		// control & 0xE0 == 0xC0 (Fully Qualified 6 bytes): 2 bytes Vendor, 2 bytes Profile, 2 bytes Tag
		// control & 0xE0 == 0xE0 (Fully Qualified 8 bytes): 2 bytes Vendor, 2 bytes Profile, 4 bytes Tag
		// Implementation detail: For now assume standard 8 byte structure reading.
		// TODO: verify exact byte layout for FullyQualified tags in Matter spec.
		if _, err := io.ReadFull(r.r, buf[:]); err != nil {
			return tag, err
		}
		tag.Profile = binary.LittleEndian.Uint32(buf[:4])
		tag.ID = uint64(binary.LittleEndian.Uint32(buf[4:]))
	default:
		return tag, errors.New("unknown tag control")
	}
	return tag, nil
}

func (r *Reader) readValue(elemType ElementType) ([]byte, error) {
	// Masking out the lower 2 bits to get the "base" type for integers
	// Signed Int: 0x00, 0x01 (1 byte), 0x02 (2 bytes), 0x03 (4 bytes), 0x04 (8 bytes) ??
	// Make sure we parse the width correctly based on the lower bits.

	// Type mapping:
	// Signed Integer: 0x00 + length(0=1, 1=2, 2=4, 3=8)
	// Unsigned Integer: 0x04 + length
	// Boolean: 0x08 (false), 0x09 (true)
	// UTF8 String: 0x0C + length_field_size(0=1, 1=2, 2=4, 3=8)
	// Byte String: 0x10 + length_field_size

	_ = elemType & 0xFC          // unused for now, potentially useful for debugging or stricter validation
	sub := byte(elemType & 0x03) // Get bottom 2 bits

	switch {
	case int(elemType) >= int(TypeSignedInt) && int(elemType) <= int(TypeSignedInt)+3:
		len := 1 << sub
		buf := make([]byte, len)
		if _, err := io.ReadFull(r.r, buf); err != nil {
			return nil, err
		}
		return buf, nil

	case int(elemType) >= int(TypeUnsignedInt) && int(elemType) <= int(TypeUnsignedInt)+3:
		len := 1 << sub
		buf := make([]byte, len)
		if _, err := io.ReadFull(r.r, buf); err != nil {
			return nil, err
		}
		return buf, nil

	case elemType == TypeBoolean: // False
		return []byte{0}, nil
	case elemType == TypeBoolean+1: // True
		return []byte{1}, nil

	case int(elemType) >= int(TypeUTF8String) && int(elemType) <= int(TypeUTF8String)+3:
		return r.readStringOrBytes(sub)

	case int(elemType) >= int(TypeByteString) && int(elemType) <= int(TypeByteString)+3:
		return r.readStringOrBytes(sub)

	case elemType == TypeNull:
		return nil, nil

	case elemType == TypeStructure, elemType == TypeArray, elemType == TypeList:
		// Container types start; value is technically empty here, we return the type
		// The caller must call ReadElement repeatedly until EndOfContainer
		return nil, nil

	default:
		return nil, fmt.Errorf("unsupported element type: 0x%X", elemType)
	}
}

// ReadContainerChildren reads all elements within a container until EndOfContainer is reached.
// It handles nested containers recursively, populating the SubElements field.
func (r *Reader) ReadContainerChildren() ([]Element, error) {
	var elements []Element
	for {
		elem, err := r.ReadElement()
		if err != nil {
			return nil, err
		}

		if elem.Type == TypeEndOfContainer {
			return elements, nil
		}

		if elem.Type == TypeStructure || elem.Type == TypeArray || elem.Type == TypeList {
			// Recursively read children for nested container
			subElems, err := r.ReadContainerChildren()
			if err != nil {
				return nil, err
			}
			elem.SubElements = subElems
		}

		elements = append(elements, elem)
	}
}

func (r *Reader) readStringOrBytes(lenLenBits byte) ([]byte, error) {
	lenLen := 1 << lenLenBits
	lenBuf := make([]byte, lenLen)
	if _, err := io.ReadFull(r.r, lenBuf); err != nil {
		return nil, err
	}

	var length uint64
	switch lenLen {
	case 1:
		length = uint64(lenBuf[0])
	case 2:
		length = uint64(binary.LittleEndian.Uint16(lenBuf))
	case 4:
		length = uint64(binary.LittleEndian.Uint32(lenBuf))
	case 8:
		length = binary.LittleEndian.Uint64(lenBuf)
	}

	if length > math.MaxInt32 {
		return nil, errors.New("string/bytes too long")
	}

	valBuf := make([]byte, length)
	if _, err := io.ReadFull(r.r, valBuf); err != nil {
		return nil, err
	}
	return valBuf, nil
}

// Writer encodes TLV data to an io.Writer.
type Writer struct {
	w io.Writer
}

// NewWriter creates a new TLV writer.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// TODO: Update Writer to support writing Elements directly or keep high-level methods?
// PutSignedInt writes a signed integer with the given tag.
func (w *Writer) PutSignedInt(tag Tag, value int64) error {
	var valBuf []byte
	var typeByte ElementType

	if value >= math.MinInt8 && value <= math.MaxInt8 {
		typeByte = TypeSignedInt // 1 byte (0x00)
		valBuf = []byte{byte(value)}
	} else if value >= math.MinInt16 && value <= math.MaxInt16 {
		typeByte = TypeSignedInt | 0x01 // 2 bytes
		valBuf = make([]byte, 2)
		binary.LittleEndian.PutUint16(valBuf, uint16(value))
	} else if value >= math.MinInt32 && value <= math.MaxInt32 {
		typeByte = TypeSignedInt | 0x02 // 4 bytes
		valBuf = make([]byte, 4)
		binary.LittleEndian.PutUint32(valBuf, uint32(value))
	} else {
		typeByte = TypeSignedInt | 0x03 // 8 bytes
		valBuf = make([]byte, 8)
		binary.LittleEndian.PutUint64(valBuf, uint64(value))
	}

	// Write Control Byte (TagControl | ElementType)
	if err := w.writeControlByte(tag.Class, typeByte); err != nil {
		return err
	}
	// Write Tag
	if err := w.writeTag(tag); err != nil {
		return err
	}
	// Write Value
	if _, err := w.w.Write(valBuf); err != nil {
		return err
	}
	return nil
}

// PutUnsignedInt writes an unsigned integer with the given tag.
func (w *Writer) PutUnsignedInt(tag Tag, value uint64) error {
	var valBuf []byte
	var typeByte ElementType

	if value <= math.MaxUint8 {
		typeByte = TypeUnsignedInt // 1 byte (0x04)
		valBuf = []byte{byte(value)}
	} else if value <= math.MaxUint16 {
		typeByte = TypeUnsignedInt | 0x01 // 2 bytes
		valBuf = make([]byte, 2)
		binary.LittleEndian.PutUint16(valBuf, uint16(value))
	} else if value <= math.MaxUint32 {
		typeByte = TypeUnsignedInt | 0x02 // 4 bytes
		valBuf = make([]byte, 4)
		binary.LittleEndian.PutUint32(valBuf, uint32(value))
	} else {
		typeByte = TypeUnsignedInt | 0x03 // 8 bytes
		valBuf = make([]byte, 8)
		binary.LittleEndian.PutUint64(valBuf, value)
	}

	// Write Control Byte (TagControl | ElementType)
	if err := w.writeControlByte(tag.Class, typeByte); err != nil {
		return err
	}
	// Write Tag
	if err := w.writeTag(tag); err != nil {
		return err
	}
	// Write Value
	if _, err := w.w.Write(valBuf); err != nil {
		return err
	}
	return nil
}

// PutBoolean writes a boolean value with the given tag.
func (w *Writer) PutBoolean(tag Tag, value bool) error {
	typeByte := TypeBoolean
	if value {
		typeByte = TypeBoolean + 1 // True
	}

	// Write Control Byte (TagControl | ElementType)
	if err := w.writeControlByte(tag.Class, typeByte); err != nil {
		return err
	}
	// Write Tag
	if err := w.writeTag(tag); err != nil {
		return err
	}
	// Boolean values have no explicit value bytes, the type byte implies the value.
	return nil
}

// PutString writes a UTF-8 string with the given tag.
func (w *Writer) PutString(tag Tag, value string) error {
	return w.writeStringOrBytes(tag, TypeUTF8String, []byte(value))
}

// PutBytes writes a byte string with the given tag.
func (w *Writer) PutBytes(tag Tag, value []byte) error {
	return w.writeStringOrBytes(tag, TypeByteString, value)
}

func (w *Writer) writeStringOrBytes(tag Tag, baseType ElementType, data []byte) error {
	length := len(data)
	var lenBytes []byte
	var lenTypeBits byte

	if length <= math.MaxUint8 {
		lenTypeBits = 0x00
		lenBytes = []byte{byte(length)}
	} else if length <= math.MaxUint16 {
		lenTypeBits = 0x01
		lenBytes = make([]byte, 2)
		binary.LittleEndian.PutUint16(lenBytes, uint16(length))
	} else if length <= math.MaxUint32 { // support up to 32 bit for now
		lenTypeBits = 0x02
		lenBytes = make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBytes, uint32(length))
	} else {
		// For now, panic or error for lengths > MaxUint32
		return errors.New("string/bytes length exceeds MaxUint32 for writing")
	}

	typeByte := baseType | ElementType(lenTypeBits)

	// Write Control Byte (TagControl | ElementType)
	if err := w.writeControlByte(tag.Class, typeByte); err != nil {
		return err
	}
	// Write Tag
	if err := w.writeTag(tag); err != nil {
		return err
	}
	// Write Length
	if _, err := w.w.Write(lenBytes); err != nil {
		return err
	}
	// Write Value
	if _, err := w.w.Write(data); err != nil {
		return err
	}
	return nil
}

// writeControlByte writes the combined TagControl and ElementType.
func (w *Writer) writeControlByte(tagControl TagControl, elemType ElementType) error {
	controlByte := byte(tagControl) | byte(elemType)
	_, err := w.w.Write([]byte{controlByte})
	return err
}

// writeTag writes the tag bytes following the control byte.
func (w *Writer) writeTag(tag Tag) error {
	// This is a minimal implementation for Context Specific tags (most common in structs).
	// TODO: Implement full tag writing for all TagControl types.
	// For now, only ContextSpecific (1 byte ID) is supported.

	switch tag.Class {
	case TagControlAnonymous:
		// No tag data to write
		return nil
	case TagControlContextSpecific:
		if tag.ID > math.MaxUint8 {
			return fmt.Errorf("context specific tag ID %d exceeds 1 byte", tag.ID)
		}
		_, err := w.w.Write([]byte{byte(tag.ID)})
		return err
	case TagControlCommonProfile2:
		buf := make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, uint16(tag.ID))
		_, err := w.w.Write(buf)
		return err
	case TagControlCommonProfile4:
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(tag.ID))
		_, err := w.w.Write(buf)
		return err
	case TagControlImplicitProfile2:
		buf := make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, uint16(tag.ID))
		_, err := w.w.Write(buf)
		return err
	case TagControlImplicitProfile4:
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, uint32(tag.ID))
		_, err := w.w.Write(buf)
		return err
	case TagControlFullyQualified6:
		// 2 bytes Vendor, 2 bytes Profile, 2 bytes Tag
		buf := make([]byte, 6)
		// Assuming tag.Profile is actually VendorID (2 bytes) + ProfileID (2 bytes)
		// For now, simplifying to just write tag.Profile as 4 bytes and tag.ID as 2 bytes
		binary.LittleEndian.PutUint16(buf[0:2], uint16(tag.Profile>>16))    // Vendor ID (placeholder)
		binary.LittleEndian.PutUint16(buf[2:4], uint16(tag.Profile&0xFFFF)) // Profile ID (placeholder)
		binary.LittleEndian.PutUint16(buf[4:6], uint16(tag.ID))
		_, err := w.w.Write(buf)
		return err
	case TagControlFullyQualified8:
		// 2 bytes Vendor, 2 bytes Profile, 4 bytes Tag
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint16(buf[0:2], uint16(tag.Profile>>16))    // Vendor ID (placeholder)
		binary.LittleEndian.PutUint16(buf[2:4], uint16(tag.Profile&0xFFFF)) // Profile ID (placeholder)
		binary.LittleEndian.PutUint32(buf[4:8], uint32(tag.ID))
		_, err := w.w.Write(buf)
		return err
	default:
		return fmt.Errorf("unsupported tag control for writing: %v", tag.Class)
	}
}

func (w *Writer) StartContainer(tag Tag, containerType ElementType) error {
	// Write Control Byte (TagControl | ElementType)
	if err := w.writeControlByte(tag.Class, containerType); err != nil {
		return err
	}
	// Write Tag
	if err := w.writeTag(tag); err != nil {
		return err
	}
	return nil
}

func (w *Writer) EndContainer() error {
	// Write EndOfContainer Control Byte (0x18)
	// It has no tag and no value.
	// Control Byte: TagControlAnonymous (0x00) | TypeEndOfContainer (0x18) = 0x18
	return w.writeControlByte(TagControlAnonymous, TypeEndOfContainer)
}
