/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package zlib

import (
	"encoding/json"
	"github.com/zmap/zgrab/ztools/processing"
)

// GrabWorker implements ztools.processing.Worker
type GrabWorker struct {
	success uint
	failure uint

	statuses chan status

	config *Config
}

type status uint

const (
	status_success status = iota
	status_failure status = iota
)

func (g *GrabWorker) Success() uint {
	return g.success
}

func (g *GrabWorker) Failure() uint {
	return g.failure
}

func (g *GrabWorker) Total() uint {
	return g.success + g.failure
}

func (g *GrabWorker) RunCount() uint {
	return g.config.ConnectionsPerHost
}

func (g *GrabWorker) Done() {
	close(g.statuses)
}

func (g *GrabWorker) MakeHandler(id uint) processing.Handler {
	return func(v interface{}) interface{} {
		target, ok := v.(GrabTarget)
		if !ok {
			return nil
		}
		grab := GrabBanner(g.config, &target)
		s := grab.status()
		g.statuses <- s
		return grab
	}
}

func NewGrabWorker(config *Config) processing.Worker {
	w := new(GrabWorker)
	w.statuses = make(chan status, config.Senders*4)
	w.config = config
	go func() {
		for s := range w.statuses {
			switch s {
			case status_success:
				w.success++
			case status_failure:
				w.failure++
			default:
				continue
			}
		}
	}()
	return w
}

type grabMarshaler struct{}

func (gm *grabMarshaler) Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func NewGrabMarshaler() processing.Marshaler {
	return new(grabMarshaler)
}
