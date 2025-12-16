package tlv

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestDecode(t *testing.T) {
	type TestStruct struct {
		IntVal    int64  `tlv:"1"`
		UintVal   uint64 `tlv:"2"`
		BoolVal   bool   `tlv:"3"`
		StringVal string `tlv:"4"`
	}

	tests := []struct {
		name    string
		hexData string
		target  interface{}
		want    interface{}
		wantErr bool
	}{
		{
			name: "Simple Struct",
			// 15 (Start Container)
			// 20 01 2a (Tag 1, Signed 1 byte, 42)    <-- Fixed from 24 (Unsigned)
			// 24 02 64 (Tag 2, Unsigned 1 byte, 100) <-- Correct
			// 29 03    (Tag 3, Bool True)
			// 2c 04 04 74 65 73 74 (Tag 4, String "test")
			hexData: "1520012a24026429032c04047465737418",
			target:  &TestStruct{},
			want: &TestStruct{
				IntVal:    42,
				UintVal:   100,
				BoolVal:   true,
				StringVal: "test",
			},
		},
		{
			name: "Integer Overflow Check",
			// Context(1): Int(1 byte) = 127. Target is int8.
			// 20 01 7f  (20 = Signed Int 1 Byte)
			hexData: "1520017f18",
			target: &struct {
				Val int8 `tlv:"1"`
			}{},
			want: &struct {
				Val int8 `tlv:"1"`
			}{Val: 127},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := hex.DecodeString(tt.hexData)
			if err != nil {
				t.Fatalf("Failed to decode hex data: %v", err)
			}

			r := NewReader(bytes.NewReader(data))
			root, err := r.ReadElement()
			if err != nil {
				t.Fatalf("ReadElement() error = %v", err)
			}

			if root.Type == TypeStructure || root.Type == TypeArray || root.Type == TypeList {
				subElems, err := r.ReadContainerChildren()
				if err != nil {
					t.Fatalf("ReadContainerChildren() error = %v", err)
				}
				root.SubElements = subElems
			}

			if err := Decode(root, tt.target); (err != nil) != tt.wantErr {
				t.Errorf("Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && !reflect.DeepEqual(tt.target, tt.want) {
				t.Errorf("Decode() got = %v, want %v", tt.target, tt.want)
			}
		})
	}
}
