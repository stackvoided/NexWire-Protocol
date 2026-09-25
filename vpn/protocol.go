package main

import (
	"encoding/binary"
	"errors"
)

const (
	MsgTypeHandshakeInit byte = 0x01
	MsgTypeHandshakeResp byte = 0x02
	MsgTypeData          byte = 0x03
	MsgTypeKeepalive     byte = 0x04

	HeaderSize = 13 // Type (1B) + Seq (8B) + SessionID (4B)
)

type PacketHeader struct {
	Type      byte
	Sequence  uint64
	SessionID uint32
}

func EncodeHeader(h PacketHeader, out []byte) {
	out[0] = h.Type
	binary.BigEndian.PutUint64(out[1:9], h.Sequence)
	binary.BigEndian.PutUint32(out[9:13], h.SessionID)
}

func DecodeHeader(data []byte) (PacketHeader, error) {
	if len(data) < HeaderSize {
		return PacketHeader{}, errors.New("packet buffer smaller than header size")
	}
	return PacketHeader{
		Type:      data[0],
		Sequence:  binary.BigEndian.Uint64(data[1:9]),
		SessionID: binary.BigEndian.Uint32(data[9:13]),
	}, nil
}

type HandshakeMessage struct {
	EphPublicKey [32]byte
	Timestamp    int64
	HMAC         [32]byte
}

func MarshalHandshake(msg HandshakeMessage) []byte {
	buf := make([]byte, 72)
	copy(buf[0:32], msg.EphPublicKey[:])
	binary.BigEndian.PutUint64(buf[32:40], uint64(msg.Timestamp))
	copy(buf[40:72], msg.HMAC[:])
	return buf
}

func UnmarshalHandshake(data []byte) (HandshakeMessage, error) {
	var msg HandshakeMessage
	if len(data) < 72 {
		return msg, errors.New("invalid handshake length")
	}
	copy(msg.EphPublicKey[:], data[0:32])
	msg.Timestamp = int64(binary.BigEndian.Uint64(data[32:40]))
	copy(msg.HMAC[:], data[40:72])
	return msg, nil
}
