package opcua

import (
	"encoding/hex"
	"strconv"
)


func Checkerr(err error) error{
	if err != nil {
	    return err
	}
	return nil
}

// function to convert and parse little endian to integer32+
func ParseLittleEndian(s string) int{
	tmp := s[6:8] + s[4:6] + s[2:4] + s[0:2]
	length64, _ := strconv.ParseInt(tmp, 16, 32)
	length := int(length64)
	return length
}

// function to parse pascal strings used in opcua, pascal string are in form: [4 byte length ULInt32|actual string]
func Process_pascal_string(anchor int,s string) (string,int){
	
	length := ParseLittleEndian(s[anchor:anchor+8])*2; anchor+=8
	uri, _ := hex.DecodeString(s[anchor:anchor+length]); anchor+=length
	return string(uri),anchor
}

// process the text encryption mask
func Process_text_enc_mask(anchor int,s string) (string,int){

		text_enc_mask := s[anchor:anchor+2] ; anchor+=2

		if (text_enc_mask == "02"){
			text_length := ParseLittleEndian(s[anchor:anchor+8])*2 ; anchor+=8
			text, _ := hex.DecodeString(s[anchor:anchor+text_length]); anchor+=text_length
			return string(text),anchor
		}
		if (text_enc_mask == "01"){
			anchor+=2
			return string(s[anchor-2:anchor]),anchor
		}
		return s,anchor
}

// process application type
func Process_application_type(anchor int,s string) (string,int){
		
	appl_type := s[anchor:anchor+8] ; anchor+=8
	
	if(appl_type == "00000000"){
		appl_type = "Server"
	}else if(appl_type == "00000001"){
		appl_type = "Client"
	}else if(appl_type == "00000002"){
		appl_type = "ClientAndServer"
	}else if(appl_type == "00000003"){
		appl_type = "DiscoveryServer"
	}
	
	return appl_type,anchor
}


func Process_opcua_string(anchor int,s string) (string,int){
	
	uri_length := s[anchor:anchor+8] 
	
	if (uri_length == "ffffffff"){
		anchor+=8
		return s[anchor-8:anchor],anchor
	}else{
		return Process_pascal_string(anchor,s)
	}
	
	return "nil",0
}

func inttohex(i int) string {
    i64 := int64(i)
	return strconv.FormatInt(i64, 16) // base 16 for hexadecima
  }

// calculate message size
func message_size(i int)string{
	if(i<255){
		return string(inttohex(i)) + "000000"
	}else{
		return inttohex(i)[2:4] + inttohex(i)[0:2] + "0000"
	}
	return "nil"
}

