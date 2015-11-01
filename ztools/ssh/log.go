/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package ssh

// HandshakeLog contains detailed information about each step of the
// SSH handshake, and can be encoded to JSON.
type HandshakeLog struct {
	ClientProtocol        *ProtocolAgreement            `json:"client_protocol,omitempty"`
	ServerProtocol        *ProtocolAgreement            `json:"server_protocol,omitempty"`
	ClientKexExchangeInit *KeyExchangeInit              `json:"client_key_exchange_init,omitempty"`
	ServerKeyExchangeInit *KeyExchangeInit              `json:"server_key_exchange_init,omitempty"`
	Algorithms            *AlgorithmSelection           `json:"algorithms,omitempty"`
	KexDHGroupRequest     *KeyExchangeDHGroupRequest    `json:"key_exchange_dh_group_request,omitempty"`
	KexDHGroupParams      *KeyExchangeDHGroupParameters `json:"key_exchange_dh_group_params,omitempty"`
	KexDHGroupInit        *KeyExchangeDHGroupInit       `json:"key_exchange_dh_group_init,omitempty"`
	KexDHGroupReply       *KeyExchangeDHGroupReply      `json:"key_exchange_dh_group_reply,omitempty"`
	DHInit                *KeyExchangeDHInit            `json:"key_exchange_dh_init,omitempty"`
	DHReply               *KeyExchangeDHInitReply       `json:"key_exchange_dh_reply,omitempty"`
}

type AlgorithmSelection struct {
	KexAlgorithm     string `json:"key_exchange_algorithm,omitempty"`
	HostKeyAlgorithm string `json:"host_key_algorithm,omitempty"`
}
