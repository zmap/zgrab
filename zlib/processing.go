package zlib

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"ztools/processing"
)

type grabTargetDecoder struct {
	reader *csv.Reader
}

func (gtd *grabTargetDecoder) DecodeNext() (interface{}, error) {
	record, err := gtd.reader.Read()
	if err != nil {
		return nil, err
	}
	if len(record) < 1 {
		return nil, errors.New("Invalid grab target (no fields)")
	}
	var target GrabTarget
	target.Addr = net.ParseIP(record[0])
	if target.Addr == nil {
		return nil, fmt.Errorf("Invalid IP address %s", record[0])
	}

	if len(record) >= 2 {
		target.Domain = record[1]
	}
	return target, nil
}

func NewGrabTargetDecoder(reader io.Reader) processing.Decoder {
	csvReader := csv.NewReader(reader)
	d := grabTargetDecoder{
		reader: csvReader,
	}
	return &d
}

type grabWorker struct {
	config     *Config
	progresses []GrabProgress
	sync.Mutex
}

func (w *grabWorker) MakeHandler(id uint) processing.Handler {
	return func(v interface{}) interface{} {
		target, ok := v.(GrabTarget)
		if !ok {
			return nil
		}
		grab := GrabBanner(w.config, &target)
		if grab.IsSuccessful() {
			w.progresses[id].success++
		} else {
			w.progresses[id].failure++
		}
		return grab
	}
}

func (w *grabWorker) Progress() processing.Progress {
	progress := new(GrabProgress)
	for _, p := range w.progresses {
		progress.success += p.success
		progress.failure += p.failure
	}
	return progress
}

func NewGrabWorker(config *Config, senders uint) processing.Worker {
	w := grabWorker{
		config:     config,
		progresses: make([]GrabProgress, senders),
	}
	return &w
}
