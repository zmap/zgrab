/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package zlib

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
