package banner

import (
	"os"
	"log"
	"encoding/json"
)

type OutputEncoding uint8

const (
	stringFlag OutputEncoding = iota
	hexFlag OutputEncoding = iota
	base64Flag OutputEncoding = iota
)

type OutputConfig struct {
	ErrorLog *log.Logger
	OutputFile *os.File
}

func WriteOutput(grabChan chan Grab, config *OutputConfig) {
	enc := json.NewEncoder(config.OutputFile)
	for grab := range grabChan {
		if err := enc.Encode(&grab); err != nil {
			config.ErrorLog.Print(err)
		}
	}
}
