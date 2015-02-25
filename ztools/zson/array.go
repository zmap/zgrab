package zson

import (
	"encoding/json"
	"errors"
	"fmt"
)

type StringOrArray []string

func (s StringOrArray) MarshalJSON() ([]byte, error) {
	if len(s) == 1 {
		return json.Marshal(s[0])
	}
	arr := []string(s)
	return json.Marshal(arr)
}

func (s *StringOrArray) UnmarshalJSON(b []byte) error {
	var raw interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	switch raw.(type) {
	case nil:
		*s = make([]string, 0)
	case string:
		out := make([]string, 1)
		out[0] = raw.(string)
		*s = out
	case []interface{}:
		arr := raw.([]interface{})
		out := make([]string, len(arr))
		for idx, elt := range arr {
			switch t := elt.(type) {
			case string:
				out[idx] = elt.(string)
			default:
				return fmt.Errorf("Error: element %d of array is a %v, (expected string)", idx, t)
			}
		}
		*s = out
	default:
		return errors.New("Not a string or an array")
	}
	return nil
}

func (s *StringOrArray) Empty() bool {
	if s == nil {
		return true
	}
	if *s == nil {
		return true
	}
	if len(*s) == 0 {
		return true
	}
	return false
}
