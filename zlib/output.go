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
	"log"
	"os"
)

type OutputConfig struct {
	OutputFile *os.File
	ErrorLog   *log.Logger
}

func WriteOutput(grabChan chan Grab, doneChan chan int, config *OutputConfig) {
	enc := json.NewEncoder(config.OutputFile)
	for grab := range grabChan {
		if err := enc.Encode(&grab); err != nil {
			config.ErrorLog.Print(err)
		}
	}
	doneChan <- 1
}
