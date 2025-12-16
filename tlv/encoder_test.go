package tlv

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestEncode(t *testing.T) {
	type TestStruct struct {
		IntVal    int64  `tlv:"1"`
		UintVal   uint64 `tlv:"2"`
		BoolVal   bool   `tlv:"3"`
		StringVal string `tlv:"4"`
	}

	tests := []struct {
		name    string
		input   interface{}
		wantHex string
		wantErr bool
	}{
		{
			name: "Simple Struct",
			input: &TestStruct{
				IntVal:    42,
				UintVal:   100,
				BoolVal:   true,
				StringVal: "test",
			},
			// 20 01 2a (Context 1, Signed 1 byte, 42)
			// 24 02 64 (Context 2, Unsigned 1 byte, 100)
			// 29 03    (Context 3, True)
			// 2c 04 04 74 65 73 74 (Context 4, String 1 byte len, 4, "test")
			// 18 (End Container)
			wantHex: "1520012a24026429032c04047465737418",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Marshal(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			gotHex := hex.EncodeToString(got)
			if gotHex != tt.wantHex {
				t.Errorf("Marshal() hex = %v, want %v", gotHex, tt.wantHex)
			}

			// Verify Loopback
			if !tt.wantErr {
				r := NewReader(bytes.NewReader(got))
				root, err := r.ReadElement()
				if err != nil {
					t.Fatalf("Loopback ReadElement failure: %v", err)
				}
				if root.Type == TypeStructure {
					root.SubElements, _ = r.ReadContainerChildren()
				}

				ptrVal := reflect.New(reflect.TypeOf(tt.input).Elem())
				if err := Decode(root, ptrVal.Interface()); err != nil {
					t.Fatalf("Loopback Decode failure: %v", err)
				}

				if !reflect.DeepEqual(ptrVal.Interface(), tt.input) {
					t.Errorf("Loopback mismatch.\nGot: %+v\nWant: %+v", ptrVal.Interface(), tt.input)
				}
			}
		})
	}
}
