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

package processing

import (
	"github.com/zmap/zgrab/ztools/zlog"
	"io"
	"sync"
)

type Decoder interface {
	DecodeNext() (interface{}, error)
}

type Marshaler interface {
	Marshal(interface{}) ([]byte, error)
}

type Worker interface {
	MakeHandler(uint) Handler
	Success() uint
	Failure() uint
	Total() uint
	Done()
	RunCount() uint
}

type Handler func(interface{}) interface{}

func Process(in Decoder, out io.Writer, w Worker, m Marshaler, workers uint) {
	processQueue := make(chan interface{}, workers*4)
	outputQueue := make(chan []byte, workers*4)

	// Create wait groups
	var workerDone sync.WaitGroup
	var outputDone sync.WaitGroup
	workerDone.Add(int(workers))
	outputDone.Add(1)

	// Start the output encoder
	go func() {
		for result := range outputQueue {
			if _, err := out.Write(result); err != nil {
				panic(err.Error())
			}
			if _, err := out.Write([]byte("\n")); err != nil {
				panic(err.Error())
			}
		}
		outputDone.Done()
	}()
	// Start all the workers
	for i := uint(0); i < workers; i++ {
		handler := w.MakeHandler(i)
		runCount := w.RunCount()
		go func(handler Handler) {
			for obj := range processQueue {
				for run := uint(0); run < runCount; run++ {
					result := handler(obj)
					enc, err := m.Marshal(result)
					if err != nil {
						panic(err.Error())
					}
					outputQueue <- enc
				}
			}
			workerDone.Done()
		}(handler)
	}
	// Read the input, send to workers
	for {
		obj, err := in.DecodeNext()
		if err == io.EOF {
			break
		} else if err != nil {
			zlog.Error(err)
		}
		processQueue <- obj
	}
	close(processQueue)
	workerDone.Wait()
	close(outputQueue)
	outputDone.Wait()
	w.Done()
}
