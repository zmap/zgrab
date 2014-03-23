package banner

import (
	"fmt"
	"os"
	"encoding/hex"
	"encoding/json"
	"encoding/base64"
	"errors"
)

type bannerOutput struct {
	Addr string 	`json:"host"`
	Err error   	`json:"error"`
	Encoding string `json:"encoding"`
	Data string     `json:"data"`
}

type ResultConverter interface {
	convert(*Result) *bannerOutput
}

type stringConverter struct {}
type base64Converter struct {}
type hexConverter struct {}

func (_ stringConverter) convert(res *Result) *bannerOutput {
	out := new(bannerOutput)
	out.Addr = res.Addr
	out.Err = res.Err
	out.Encoding = "string"
	out.Data = string(res.Data)
	return out
}

func (_ base64Converter) convert(res *Result) *bannerOutput {
	out := new(bannerOutput)
	out.Addr = res.Addr
	out.Err = res.Err
	out.Encoding = "base64"
	out.Data = base64.StdEncoding.EncodeToString(res.Data)
	return out
}

func (_ hexConverter) convert(res *Result) *bannerOutput {
	out := new(bannerOutput)
	out.Addr = res.Addr
	out.Err = res.Err
	out.Encoding = "hex"
	out.Data = hex.EncodeToString(res.Data)
	return out
}

type bannerEncoder struct {
	enc *json.Encoder
	converter ResultConverter
}

func (be *bannerEncoder) Encode(r *Result) error {
	value := be.converter.convert(r)
	return be.enc.Encode(value)
}

func NewResultConverter(encoding string) (ResultConverter, error) {
	switch encoding {
	case "string":
		return stringConverter{}, nil
	case "base64":
		return base64Converter{}, nil
	case "hex":
		return hexConverter{}, nil
	default:
		return nil, errors.New("Invalid encoding " + encoding)
	}
}

func newBannerEncoder(f *os.File, converter ResultConverter) bannerEncoder {
	be := bannerEncoder{json.NewEncoder(f), converter}
	return be
}

func WriteOutput(resultChan chan Result, converter ResultConverter, f *os.File) {
	enc := newBannerEncoder(f, converter)
	for result := range resultChan {
		if err := enc.Encode(&result); err != nil {
			fmt.Fprintln(os.Stderr, "Error: JSON ", err)
		}
	}
}


