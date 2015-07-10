/*
 * ZGrab Copyright 2015 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

package zlib

type ConnectEvent struct {
}

var ConnectEventType = EventType{
	TypeName:         CONNECTION_EVENT_CONNECT_NAME,
	GetEmptyInstance: newConnectEvent,
}

func (ce *ConnectEvent) GetType() EventType {
	return ConnectEventType
}

func newConnectEvent() EventData {
	return new(ConnectEvent)
}
