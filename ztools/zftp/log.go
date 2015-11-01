/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package zftp

type FTPLog struct {
	Banner      string `json:"banner,omitempty"`
	AuthTLSResp string `json:"auth_tls_resp,omitempty"`
	AuthSSLResp string `json:"auth_ssl_resp,omitempty"`
}
