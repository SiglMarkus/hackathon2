package main


import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	handle, err := pcap.OpenLive("enp0s3", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	//Filter only IP Protocol packages
	bpfInstructions := []pcap.BPFInstruction{
		{ 0x28, 0, 0, 0x0000000c },
		{ 0x15, 0, 1, 0x00000800 },
		{ 0x6, 0, 0, 0x00040000 },
		{ 0x6, 0, 0, 0x00000000 },
	}

	if err := handle.SetBPFInstructionFilter(bpfInstructions); err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		fmt.Println(packet.String())
	}
}
