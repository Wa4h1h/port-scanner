package tcp

import (
	"bytes"
	"encoding/binary"
)

type TCPHeader struct {
	SeqNum    uint32
	AckNum    uint32
	SrcPort   uint16
	DstPort   uint16
	Window    uint16
	Checksum  uint16
	Ptr       uint16
	CtrlFlags uint8
	Offset    uint8
	Reserved  uint8
	Options   []byte
}

type Packet struct {
	Header *TCPHeader
	Body   []byte
}

func Marshal(t *Packet) ([]byte, error) {
	b := new(bytes.Buffer)

	binary.Write(b, binary.BigEndian, t.Header.SrcPort)
	binary.Write(b, binary.BigEndian, t.Header.DstPort)
	binary.Write(b, binary.BigEndian, t.Header.SeqNum)
	binary.Write(b, binary.BigEndian, t.Header.AckNum)

	leftPart := uint16(t.Header.Offset)<<12 |
		uint16(t.Header.Reserved)<<6 |
		uint16(t.Header.CtrlFlags)

	binary.Write(b, binary.BigEndian, leftPart)
	binary.Write(b, binary.BigEndian, t.Header.Window)
	binary.Write(b, binary.BigEndian, t.Header.Checksum)
	binary.Write(b, binary.BigEndian, t.Header.Ptr)
	binary.Write(b, binary.BigEndian, t.Header.Options)
	binary.Write(b, binary.BigEndian, t.Body)

	return b.Bytes(), nil
}

func Unmarshal(b []byte) (*Packet, error) {
	return nil, nil
}

func CheckSum(data []byte, SrcIP uint32, DstIP uint32) uint16 {
	var (
		sum        uint32
		toSumBytes = make([]byte, 0)
	)

	pHeaderBytes := new(bytes.Buffer)

	binary.Write(pHeaderBytes, binary.BigEndian, SrcIP)
	binary.Write(pHeaderBytes, binary.BigEndian, DstIP)
	binary.Write(pHeaderBytes, binary.BigEndian, uint8(0))
	binary.Write(pHeaderBytes, binary.BigEndian, uint8(6))
	binary.Write(pHeaderBytes, binary.BigEndian, uint16(len(data)))

	toSumBytes = append(toSumBytes, pHeaderBytes.Bytes()...)
	toSumBytes = append(toSumBytes, data...)

	for i := 0; i < len(toSumBytes); i += 2 {
		sum += +uint32(toSumBytes[i]) + uint32(toSumBytes[i+1])
	}

	if len(toSumBytes)%2 != 0 {
		sum += uint32(toSumBytes[len(toSumBytes)-1])
	}

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return ^uint16(sum)
}
