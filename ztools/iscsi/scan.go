package iscsi

import (
	"net"
	"fmt"
	"regexp"
)

// FIXME, this is hacky and may not be very resilient
var iscsiTargetRegex = regexp.MustCompile(`TargetName=([^\x00]+)[^T]*TargetAddress=([A-Za-z0-9\./:]+)`)
/*var (
	iscsiTargetNameRegex = regexp.MustCompile(`TargetName=([^\x00]+)`)
	iscsiTargetAddressRegex = regexp.MustCompile(`TargetAddress=([A-Za-z0-9\./:]+)`)
)*/


func Scan(conn net.Conn, config *ISCSIConfig) (AuthLog, error) {
	authlog := AuthLog{conn.RemoteAddr().String(), []Target{}, false}
	// FIXME, there is too much hardcoded stuff going on here, needs more command line flags
	body := fmt.Sprintf("%x00%x00%x00%x00%x00%x00%x00%x00%x00%x00%x",
		"InitiatorName=iqn.1994-05.com.redhat:4fd2932635a0",
		// Apparently login only accepts names that are % 4 == 1 bytes long.
		// Integer division plus padding to the rescue!
		"InitiatorAlias=" + fmt.Sprintf("%0" + fmt.Sprint(len(config.LocalLogin) / 4 * 4 + 5)  + "s", config.LocalLogin),
		"SessionType=Discovery",
		"HeaderDigest=None",
		"DataDigest=None",
		"DefaultTime2Wait=2",
		"DefaultTime2Retain=0",
		"IFMarker=No",
		"OFMarker=No",
		"ErrorRecoveryLevel=0",
		"MaxRecvDataSegmentLength=32768",
	)
	header := fmt.Sprintf("438700000000%04x00023D00000000000000000000000000000000010000000000000000000000000000000000000000", len(body)/2)
	data := []byte{}
	fmt.Sscanf(header+body+"0000", "%x", &data)
	conn.Write(data)
	res := make([]byte, 1024)
	_, err := conn.Read(res)
	if err != nil {
		authlog.HadError = true
		return authlog, err
	}

	// fixme, "All" is hardcoded for now)
	body = fmt.Sprintf("53656e64546172676574733d%x", "All")
	all := fmt.Sprintf("048000000000%04x000000000000000000000001ffffffff000000010000000100000000000000000000000000000000%s00", (len(body) / 2) + 1, body)
	data = []byte{}
	fmt.Sscanf(all, "%x", &data)
	conn.Write(data)
	res = make([]byte, 1024)
	_, err = conn.Read(res) //c.readUntilRegex(res, iscsiTargetNameRegex)
	//c.grabData.Banner = string(res[0:n])
	if err != nil {
		authlog.HadError = true
		return authlog, err
	}
	var haderror error
	for _, bs := range iscsiTargetRegex.FindAllSubmatch(res, -1) {
		//for i, b := range bs {
		//fmt.Println(i, string(b), len(bs), n)
	//}

		conn2, err := net.Dial("tcp", conn.RemoteAddr().String())
		defer conn2.Close()
		if err != nil {
			authlog.Targets = append(authlog.Targets, Target{string(bs[1]), string(bs[2]), false, true})
			haderror = err
			continue
		}
		body = fmt.Sprintf(
			"%x00%x00%x00%x00%x00%x00%x00%x00%x00%x00%x00%x00%x00%x00%x00%x00%x00%x00%x00%x",
			"InitiatorName=iqn.1994-05.com.redhat:4fd2932635a0", //1
			"InitiatorAlias=0000" + config.LocalLogin, //2
			"TargetName=" + string(bs[1]), //3
			"SessionType=Normal", //4
			"HeaderDigest=None", //5
			"DataDigest=None", //6
			"DefaultTime2Wait=2", //7
			"DefaultTime2Retain=0", //8
			"IFMarker=No", //9
			"OFMarker=No", //10
			"ErrorRecoveryLevel=0", //11
			"InitialR2T=No", //12
			"ImmediateData=Yes", //13
			"MaxBurstLength=16776192", //14
			"FirstBurstLength=262144", //15
			"MaxOutstandingR2T=1", //16
			"MaxConnections=1", //17
			"DataPDUInOrder=Yes", //18
			"DataSequenceInOrder=Yes", //19
			"MaxRecvDataSegmentLength=262144", //20
		)
		header = fmt.Sprintf("438700000000%04x00023D00000000000000000000000000000000010000000000000000000000000000000000000000", len(body)/2)
		data = []byte{}
		fmt.Sscanf(header+body+"0000", "%x", &data)
		conn2.Write(data)
		res = make([]byte, 1024)
		_, err = conn2.Read(res)
		if err != nil {
			authlog.Targets = append(authlog.Targets, Target{string(bs[1]), string(bs[2]), false, true})
			haderror = err
			continue
		}
		if res[36] == 0 && res[37] == 0 {
			authlog.Targets = append(authlog.Targets, Target{string(bs[1]), string(bs[2]), true, false})
		} else {
			authlog.Targets = append(authlog.Targets, Target{string(bs[1]), string(bs[2]), false, false})
		}
		
	}
	if haderror != nil {
		authlog.HadError = true
	}
	return authlog, haderror
}
