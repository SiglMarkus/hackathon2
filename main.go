package main


import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	//Choose Network Interface
	device := "enp0s3"
	//Create Packet Sniffer
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)

	if err != nil {
		panic(err)
	}

	//Filter only IP Protocol packages
	//Created through tcpdump -dd "ip"
	bpfInstructions := []pcap.BPFInstruction{
		{ 0x28, 0, 0, 0x0000000c },
		{ 0x15, 0, 1, 0x00000800 },
		{ 0x6, 0, 0, 0x00040000 },
		{ 0x6, 0, 0, 0x00000000 },
	}


	//could also use handle.CompileBPFFilter("ip")
	//but we first tried it with the binary from tcpdump
	if err := handle.SetBPFInstructionFilter(bpfInstructions); err != nil {
		panic(err)
	}

	//get all ip packages
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	//print packet
	for packet := range packetSource.Packets() {
		/*
		for better display, here should be a few lines of string manipulation or accessing the
		relevant data direct through methods - if available

		important information would be for example:
		DestMAC
		SrcMAC
		DestIP
		SrcIP
		DestPort
		SrcPort
		packet.content
		*/
		fmt.Println(packet.String())
	}
}
