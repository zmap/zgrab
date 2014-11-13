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
