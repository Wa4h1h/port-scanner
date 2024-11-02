package tcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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

func (p *Packet) Marshal() ([]byte, error) {
	b := new(bytes.Buffer)

	err := errors.Join(binary.Write(b, binary.BigEndian, p.Header.SrcPort),
		binary.Write(b, binary.BigEndian, p.Header.DstPort),
		binary.Write(b, binary.BigEndian, p.Header.SeqNum),
		binary.Write(b, binary.BigEndian, p.Header.AckNum),
	)

	leftPart := uint16(p.Header.Offset)<<12 |
		uint16(p.Header.Reserved)<<6 |
		uint16(p.Header.CtrlFlags)

	err = errors.Join(err, binary.Write(b, binary.BigEndian, leftPart),
		binary.Write(b, binary.BigEndian, p.Header.Window),
		binary.Write(b, binary.BigEndian, p.Header.Checksum),
		binary.Write(b, binary.BigEndian, p.Header.Ptr),
		binary.Write(b, binary.BigEndian, p.Header.Options),
		binary.Write(b, binary.BigEndian, p.Body))

	return b.Bytes(), err
}

func (p *Packet) Unmarshal(b []byte) error {
	var (
		tcpHeader TCPHeader
		leftPart  uint16
	)

	buffer := bytes.NewReader(b)

	err := errors.Join(binary.Read(buffer, binary.BigEndian, &tcpHeader.SrcPort),
		binary.Read(buffer, binary.BigEndian, &tcpHeader.DstPort),
		binary.Read(buffer, binary.BigEndian, &tcpHeader.SeqNum),
		binary.Read(buffer, binary.BigEndian, &tcpHeader.AckNum),
		binary.Read(buffer, binary.BigEndian, &leftPart),
		binary.Read(buffer, binary.BigEndian, &tcpHeader.Window),
		binary.Read(buffer, binary.BigEndian, &tcpHeader.Checksum),
		binary.Read(buffer, binary.BigEndian, &tcpHeader.Ptr))
	if err != nil {
		return fmt.Errorf("error: read tcp header: %w", err)
	}

	tcpHeader.Offset = uint8(leftPart >> 12)
	tcpHeader.Reserved = uint8((leftPart >> 6) & 0x3f)
	tcpHeader.CtrlFlags = uint8(leftPart & 0x3f)

	p.Header = &tcpHeader
	p.Body = b[tcpHeader.Offset:]

	return nil
}

// CheckSum calculates TCP/IP checksum field following rfc1071
func CheckSum(data []byte, srcIP []byte, dstIP []byte) (uint16, error) {
	var (
		sum        uint32
		err        error
		toSumBytes = make([]byte, 0)
	)

	pHeaderBytes := new(bytes.Buffer)

	err = errors.Join(binary.Write(pHeaderBytes, binary.BigEndian, srcIP),
		binary.Write(pHeaderBytes, binary.BigEndian, dstIP),
		binary.Write(pHeaderBytes, binary.BigEndian, uint8(0)),
		binary.Write(pHeaderBytes, binary.BigEndian, uint8(6)),
		binary.Write(pHeaderBytes, binary.BigEndian, uint32(len(data))))
	if err != nil {
		return 0, fmt.Errorf("error: tcp/ip checksum: %w", err)
	}

	toSumBytes = append(toSumBytes, pHeaderBytes.Bytes()...)
	toSumBytes = append(toSumBytes, data...)

	for i := 0; i+1 < len(toSumBytes); i += 2 {
		sum += uint32(toSumBytes[i])<<8 + uint32(toSumBytes[i+1])
	}

	if len(toSumBytes)%2 == 1 {
		sum += uint32(toSumBytes[len(toSumBytes)-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return ^uint16(sum), nil
}

func (p *Packet) FlagIsSYNACK() bool {
	return p.Header.CtrlFlags == SYNACK
}

func (p *Packet) FlagIsRST() bool {
	return p.Header.CtrlFlags == RST ||
		p.Header.CtrlFlags == RSTACK
}
