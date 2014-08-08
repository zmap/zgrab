package banner

import (
	"os"
	"log"
	"encoding/hex"
	"encoding/json"
	"encoding/base64"
)

type TlsLog interface {

}

type OutputConfig struct {
	ErrorLog *log.Logger
	Converter ResultConverter
	OutputFile *os.File
}

type Summary struct {
	Success uint			`json:"success_count"`
	Error uint				`json:"error_count"`
	Total uint				`json:"total"`
}

type bannerOutput struct {
	Addr string 			`json:"host"`
	FirstData string	`json:"first_data"`
	Err error   			`json:"error"`
	TlsHandshakeLog TlsLog 	`json:"tls_handshake"`
	Encoding string 		`json:"encoding"`
	Data string     		`json:"data"`
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
	out.TlsHandshakeLog = res.TlsHandshakeLog
	out.Encoding = "string"
	out.Data = string(res.Data)
	out.FirstData = string(res.FirstData)
	return out
}

func (_ base64Converter) convert(res *Result) *bannerOutput {
	out := new(bannerOutput)
	out.Addr = res.Addr
	out.Err = res.Err
	out.TlsHandshakeLog = res.TlsHandshakeLog
	out.Encoding = "base64"
	out.Data = base64.StdEncoding.EncodeToString(res.Data)
	out.FirstData = base64.StdEncoding.EncodeToString(res.FirstData)
	return out
}

func (_ hexConverter) convert(res *Result) *bannerOutput {
	out := new(bannerOutput)
	out.Addr = res.Addr
	out.Err = res.Err
	out.TlsHandshakeLog = res.TlsHandshakeLog
	out.Encoding = "hex"
	out.Data = hex.EncodeToString(res.Data)
	out.FirstData = hex.EncodeToString(res.Data)
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

var (
	Converters map[string]ResultConverter
)

func init() {
	Converters = make(map[string]ResultConverter)
	Converters["string"] = stringConverter{}
	Converters["base64"] = base64Converter{}
	Converters["hex"] = hexConverter{}
}

func newBannerEncoder(f *os.File, converter ResultConverter) bannerEncoder {
	be := bannerEncoder{json.NewEncoder(f), converter}
	return be
}

func SerializeSummary(s *Summary) ([]byte, error) {
	return json.Marshal(*s)
}

func WriteOutput(resultChan chan Result, summaryChan chan Summary, config *OutputConfig) {
	summary := Summary{0, 0, 0}
	enc := newBannerEncoder(config.OutputFile, config.Converter)
	for result := range resultChan {
		if err := enc.Encode(&result); err != nil {
			config.ErrorLog.Print(err)
		}
		if result.Err == nil {
			summary.Success += 1
		} else {
			summary.Error += 1
		}
	}
	summary.Total = summary.Success + summary.Error
	// Print summary
	summaryChan <- summary

}
