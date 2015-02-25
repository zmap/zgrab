package processing

import "io"

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
}

type Handler func(interface{}) interface{}

func Process(in Decoder, out io.Writer, w Worker, m Marshaler, workers uint) {
	processQueue := make(chan interface{}, workers*4)
	outputQueue := make(chan []byte, workers*4)
	workerDone := make(chan int, workers)
	outputDone := make(chan int, 1)
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
		outputDone <- 1
	}()
	// Start all the workers
	for i := uint(0); i < workers; i++ {
		handler := w.MakeHandler(i)
		go func(handler Handler) {
			for obj := range processQueue {
				result := handler(obj)
				enc, err := m.Marshal(result)
				if err != nil {
					panic(err.Error())
				}
				outputQueue <- enc
			}
			workerDone <- 1
		}(handler)
	}
	// Read the input, send to workers
	for {
		obj, err := in.DecodeNext()
		if err == io.EOF {
			break
		}
		processQueue <- obj
	}
	close(processQueue)
	for i := uint(0); i < workers; i++ {
		<-workerDone
	}
	close(outputQueue)
	<-outputDone
	w.Done()
}
