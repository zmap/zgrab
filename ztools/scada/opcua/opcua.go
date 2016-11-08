package opcua

import (
	"net"
	"encoding/hex"
	//"fmt"
	"errors"
)

var HELqueryBytes []byte
var OSCRqueryBytes []byte
var	FSRqueryBytes []byte
var cache []string
var SecChanId string

// main function , currently only sends HEL and Open Secure Channel Request with Security Mode "None", Find Servers and Get Endpoints Request are not fully implemented yet and commented out atm
func GetOPCUAData(logStruct *OPCUALog, connection net.Conn) error {


	var err error
	HELqueryBytes, err = BuildHel()
	Checkerr(err)
	OSCRqueryBytes, err = BuildOscr()
	Checkerr(err)

	bytesWritten, err := connection.Write(HELqueryBytes)
	if bytesWritten != len(HELqueryBytes) {
		return errors.New("Unable to write OPC UA HEL query...")
	}
	Checkerr(err)

	readBuffer := make([]byte, 256)
	length, err := connection.Read(readBuffer)
	readBuffer = readBuffer[:length]
	Checkerr(err)
	
	
	// receive ACK, we have an opcua server here and continue sending an open secure channel request
	if (string(readBuffer[0:3]) == "ACK") {
		logStruct.IsOPCUA = true
		bytesWritten, err := connection.Write(OSCRqueryBytes)
		
		if bytesWritten != len(OSCRqueryBytes) {
	       return errors.New("Unable to write OPC UA Open Secure Channel Request...")
 	    }
		Checkerr(err)

		readBuffer := make([]byte, 512)
		length, err := connection.Read(readBuffer)
		readBuffer = readBuffer[:length]
		
		// server answer equals OPNF -> Server accepts Open Secure Channel Request with Security Mode None
		if (string(readBuffer[0:4]) == "OPNF"){
			SecChanId,logStruct.SecurityPolicyUri,logStruct.ServerNonce,logStruct.ServerProtocolVersion = Parse_oscr(hex.EncodeToString(readBuffer))
			

			/*
			FsrqueryBytes, err := BuildFsr(SecChanId)
			Checkerr(err)
			bytesWritten, err := connection.Write(FsrqueryBytes)
		    if bytesWritten != len(FsrqueryBytes) {
 		  	    return errors.New("Unable to write OPC UA Find Servers Request...")
 	     	}
			Checkerr(err)
			
			readBuffer := make([]byte, 512)
			length, err := connection.Read(readBuffer)
			readBuffer = readBuffer[:length]
			_, cache = Parse_fsr(hex.EncodeToString(readBuffer))
		
			logStruct.ApplicationUri = cache[0]
			logStruct.ProductUri = cache[1]
			logStruct.Text = cache[2]
			logStruct.ApplicationType = cache[3]
			logStruct.GatewayServerUri = cache[4]
			logStruct.DiscoveryProileUri = cache[5]
			logStruct.DiscoveryUrl = cache[6]
			*/
		}else{
			// answer does not equal OPNF -> Server does not support MessageSecurityMode None
			logStruct.SecurityPolicyUri = "Message Security Mode None not supported"
		}
	}

	return nil
}
