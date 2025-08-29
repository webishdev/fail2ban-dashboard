package fail2ban_client

import (
	"reflect"
	"testing"
)

func TestPy_builtins_str_Call(t *testing.T) {
	tests := []struct {
		name     string
		args     []interface{}
		expected interface{}
	}{
		{
			name:     "string argument",
			args:     []interface{}{"test"},
			expected: "test",
		},
		{
			name:     "integer argument",
			args:     []interface{}{42},
			expected: 42,
		},
		{
			name:     "boolean argument",
			args:     []interface{}{true},
			expected: true,
		},
		{
			name:     "nil argument",
			args:     []interface{}{nil},
			expected: nil,
		},
		{
			name:     "multiple arguments returns first",
			args:     []interface{}{"first", "second", "third"},
			expected: "first",
		},
		{
			name:     "empty slice argument",
			args:     []interface{}{[]string{}},
			expected: []string{},
		},
		{
			name:     "struct argument",
			args:     []interface{}{struct{ Name string }{Name: "test"}},
			expected: struct{ Name string }{Name: "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pyStr := Py_builtins_str{}
			result, err := pyStr.Call(tt.args...)

			if err != nil {
				t.Errorf("Call() error = %v, wantErr false", err)
				return
			}

			// Use deep comparison for the result
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Call() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPy_builtins_str_Call_EmptyArgs(t *testing.T) {
	pyStr := Py_builtins_str{}

	// Test with no arguments - this should panic or return error based on implementation
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Call() with no arguments should panic or handle gracefully")
		}
	}()

	_, _ = pyStr.Call()
}

func TestPy_builtins_str_Call_ConsistencyCheck(t *testing.T) {
	pyStr := Py_builtins_str{}
	testValue := "consistency_test"

	// Call multiple times with same argument to ensure consistency
	for i := 0; i < 5; i++ {
		result, err := pyStr.Call(testValue)
		if err != nil {
			t.Errorf("Call() iteration %d error = %v, wantErr false", i, err)
			return
		}
		if result != testValue {
			t.Errorf("Call() iteration %d = %v, want %v", i, result, testValue)
		}
	}
}
