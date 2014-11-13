package zgrab

import "errors"

func errorToStringPointer(err error) *string {
	if err == nil {
		return nil
	}
	s := err.Error()
	return &s
}

func stringPointerToError(s *string) error {
	if s == nil {
		return nil
	}
	return errors.New(*s)
}
