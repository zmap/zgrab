package opcua

import (
	"encoding/hex"
)

// parse open secure channel request
func Parse_oscr(s string) (string,string,string,string){

	security_policy_uri, _ := Process_opcua_string(24,s)
	server_nonce := s[len(s)-2:len(s)]
	server_prtocol_version := (s[len(s)-58:len(s)-50])
	return s[16:24],security_policy_uri,server_nonce,server_prtocol_version
}

// parse find servers request, anchor is used to fix a position in the byte string
// application array currently only works when size is 1 as this was my only possible test case
func Parse_fsr(s string) (string,[]string){
	log := make([]string, 7)  
	var anchor int = 112
	var k int = 0
	appl_arr_length := ParseLittleEndian(s[104:112])
	
	for i := 0; i < appl_arr_length; i++ {
		appl_uri,anchor := Process_opcua_string(anchor,s)
		log[k] = appl_uri; k++
		
		product_uri, anchor := Process_opcua_string(anchor,s)
		log[k] = product_uri; k++
		
		text,anchor := Process_text_enc_mask(anchor,s)
		log[k] = text; k++
		
		application_type,anchor := Process_application_type(anchor,s)
		log[k] = application_type; k++
		
		gateway_server_uri,anchor := Process_opcua_string(anchor,s)
		log[k] = gateway_server_uri; k++
		
		discovery_profile_uri,anchor := Process_opcua_string(anchor,s)
		log[k] = discovery_profile_uri; k++
		
		discovery_url_array_length := ParseLittleEndian(s[anchor:anchor+8]);anchor+=8  //selbe wie obiges array
		for j := 0; j < discovery_url_array_length; j++ {

			discovery_url, _ := Process_opcua_string(anchor,s)
			log[k] = discovery_url; k++
			}
		}
	
	return s[24:32],log // = Secure Channel ID
}

// parse get endpoints request 
func Parse_ger(s string) string{
	var anchor int = 104
	
	endpoint_array_size := ParseLittleEndian(s[anchor:anchor+8]); anchor+=8
	
	for i := 0; i < endpoint_array_size; i++ {

	var endpoint_url string
	endpoint_url, anchor = Process_opcua_string(anchor,s)
	_ = endpoint_url
	
	var application_uri string
	application_uri, anchor = Process_opcua_string(anchor,s)
	_ = application_uri
	var product_uri string
	product_uri, anchor = Process_opcua_string(anchor,s)
	_ = product_uri
	
	var text string
	text,anchor = Process_text_enc_mask(anchor,s)
	_ = text
	
	var application_type string
	application_type,anchor = Process_application_type(anchor,s)
	_ = application_type

	var gateway_server_uri string
	gateway_server_uri,anchor = Process_opcua_string(anchor,s)
	_ = gateway_server_uri

	var discovery_profile_uri string
	discovery_profile_uri,anchor = Process_opcua_string(anchor,s)
	_ = discovery_profile_uri
	
	//discovery_url_array_length := s[anchor:anchor+8] selbe wie obiges array
	anchor+=8
	
	var discovery_url string
	discovery_url,anchor = Process_opcua_string(anchor,s)
	_ = discovery_url
	
	length := ParseLittleEndian(s[anchor:anchor+8])*2; anchor+=length+8
	message_security_mode := ParseLittleEndian(s[anchor:anchor+8]); anchor+=8

	var secmode string
	if(message_security_mode == 1){
		secmode="None"
	}else if(message_security_mode == 2){
		secmode="Sign"
	}else if(message_security_mode == 3){
		secmode="SignAndEncrypt"
	}
	
	_ = secmode
	
	var security_policy_uri string
	security_policy_uri,anchor = Process_opcua_string(anchor,s)
	_ = security_policy_uri
	
	user_token_identity_array_size := ParseLittleEndian(s[anchor:anchor+8]) ; anchor+=8
	
	for j := 0; j < user_token_identity_array_size; j++ {
		//innerround := strconv.Itoa(j)
		var policy_id string
		policy_id,anchor = Process_opcua_string(anchor,s)
		_ = policy_id

		anchor+=8 //UserTokenTypeUeberspringen

		var issued_token_type string
		issued_token_type,anchor = Process_opcua_string(anchor,s)
		_ = issued_token_type
		
		var issuer_endpoint_url string
		issuer_endpoint_url,anchor = Process_opcua_string(anchor,s)
		_ = issuer_endpoint_url
		
		var security_poilcy_url string
		security_poilcy_url,anchor = Process_opcua_string(anchor,s)
		_ = security_poilcy_url
		
	}
	
	var transport_profile_uri string
	transport_profile_uri,anchor = Process_opcua_string(anchor,s)
	_ = transport_profile_uri
	
	security_level, _ :=hex.DecodeString(s[anchor:anchor+2]) ; anchor+=2
	_ = security_level
	
	}
	
	
	return s
}
