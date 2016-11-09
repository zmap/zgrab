package opcua

import (
	"encoding/hex"
)
// hello packet in hex
var hexhel string = "48454c" +				// Message Type = Hel
		    "46" +				// Chunk Type = F = Final
		    "3e000000" +			// Message Size = 62
		    "00000000" +			// Proto Version = 0
		    "00000100" +			// ReceivedBufferSize = 65636
		    "00000100" +			// SendBufferSize = 65636
		    "00000001" +			// MaxMsgSize = 167
		    "88130000" +			// MaxChunkCount = 5000
	            "00000000"				// Endpoint URL = OPC Null String

// function to build hello ; calculates message size if endpoint url is changed in the future
func BuildHel() ([]byte,error){
	hel , err := hex.DecodeString(hexhel[:8] + message_size(len(hexhel)/2) +  hexhel[16:])
	return hel,err
}

// same for open secure channel request
var hexoscr string = "4f504e" + 			// Message Type = OPN
		     "46" +				// Chunk Type = F = Final
		     "85000000" +			// Message Size = 133
		     "00000000" +			// Secure Channel ID
		     "2f000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412f5365637572697479506f6c696379234e6f6e65" + // Length.ULInt32|Security Policy Uri
		     "ffffffff" +			// Sender Cert
		     "ffffffff" +			// Receiver Cert
		     "33000000" +			// Seq Nr
		     "03000000" +			// Request ID
		     "0100be01" +			// Enc mask = Open Secure Channel Request
		     "0000" + 				// Authentikation Token
		     "08cb34bced0cd201" +		// Timestamp (only for diagnostic purpose)
		     "00000000"	+			// Request Handle
		     "00000000" +			// Return Diagnostics
		     "ffffffff" +			// Audit Entry ID
		     "00000000" +			// Timeout Hint
		     "000000"	+			// Additional Header
		     "00000000" +			// Client Protocol Version
		     "00000000" +			// Security Token Request Type 
		     "01000000" +			// Message Security Mode = 1 = None
		     "01000000" +			// Some Padding ????
		     "00" +				// Client Nonce 00
		     "e0930400" 			// Requested Lifetime

// same as hello
func BuildOscr()([]byte,error){
	oscr,err := hex.DecodeString(hexoscr[:8] + message_size(len(hexoscr)/2) +  hexoscr[16:])	
	return oscr,err
}	

// Find Servers Request
var  hexfsr string = "4d5347" + 			// Message Type = MSG
		     "46"     +				// Chunk Type = F = Final
		     "63000000" +			// Message Size = 99
		     "ec8d0000" +			// Secure Channel ID
		     "01000000" +			// Security Token ID
		     "00000000" +			// Security Sequence Number = 0
		     "01000000" +			// Security Request ID
		     "0100a601" +			// Expand Node ID
		     "000008cb34bced0cd2010000000000000000ffffffff10270000000000" + // Request Header w timestamp & stuff
		     //"1e0000006f70632e7463703a2f2f3139322e3136382e3235352e34383a3438303230" + // Length.ULInt32|Endpoint URL
		     "00000000000000000000000000000000000000000000000000000000000000000000" +  // Endpoint URL OPCUA Empty String
		     "0000000000000000"

// build find servers ; Secure Channel ID is included
func BuildFsr(SecChanId string)([]byte,error){
	fsr,err := hex.DecodeString(hexfsr[:8] + message_size(len(hexfsr)/2) + SecChanId +  hexfsr[24:]) 
	return fsr,err
}

// get endpoints request
var hexger string = "4d5347"  +				// Message Type = MSG
		    "46" +					// Chunk Type = F = Final
		    "63000000" +			// Message Size = 99
		    "ec8d0000" +			// Secure Channel ID
		    "01000000" +			// Security Token ID
		    "34000000" +			// Security Sequence Number = 0
		    "02000000" +			// Security Request ID
		    "0100ac01" +			// Expand Node ID
		    "000008cb34bced0cd2010100000000000000ffffffff10270000000000" + // Request Header w timestamp & stuff
		   //"1e0000006f70632e7463703a2f2f3139322e3136382e3235352e34383a3438303230" +  // Length.ULInt32|Endpoint URL
		    "00000000" +  // Endpoint URL OPCUA Empty String
		    "0000000000000000"

// build ger, Secure Channel ID + Security Token ID included
func BuildGer(SecChanId string,SecTokenId string)([]byte,error){
	ger,err := hex.DecodeString(hexger[:8] + message_size(len(hexger)/2) + SecChanId + SecTokenId +  hexger[32:]) 
	return ger,err
}

// close Secure Channel Request
var hexcscr string = "434c4f4639000000d5b700000100000035000000030000000100c4010000d031564cb30dd2010000000000000000ffffffff00000000000000"

func BuildCscr(SecChanId string,SecTokenId string)([]byte,error){
	cscr, err := hex.DecodeString(hexcscr[:16] + SecChanId + SecTokenId + hexcscr[32:])
	return cscr,err
}
