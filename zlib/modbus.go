package zlib

import "encoding/json"

type ModbusEvent struct {
	Response []byte
}

var ModbusEventType = EventType{
	TypeName:         CONNECTION_EVENT_MODBUS,
	GetEmptyInstance: func() EventData { return new(ModbusEvent) },
}

func (m *ModbusEvent) GetType() EventType {
	return ModbusEventType
}

type encodedModbusEvent struct {
	Response []byte `json:"response"`
}

func (m *ModbusEvent) MarshalJSON() ([]byte, error) {
	e := encodedModbusEvent{
		Response: m.Response,
	}
	return json.Marshal(&e)
}

func (m *ModbusEvent) UnmarshalJSON(b []byte) error {
	e := new(encodedModbusEvent)
	if err := json.Unmarshal(b, e); err != nil {
		return err
	}
	m.Response = e.Response
	return nil
}
