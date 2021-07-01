package packets

import (
	"net"
	"strings"

	"github.com/evilsocket/islazy/str"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const MDNSPort = 5353

var (
	MDNSDestMac = net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}
	MDNSDestIP  = net.ParseIP("224.0.0.251")
)

func MDNSGetMeta(pkt gopacket.Packet) map[string]string {
	meta := make(map[string]string)

	defer func() {
		if r := recover(); r != nil {
			meta = nil
		}
	}()

	if ludp := pkt.Layer(layers.LayerTypeUDP); ludp != nil {
		if udp := ludp.(*layers.UDP); udp != nil && udp.SrcPort == MDNSPort && udp.DstPort == MDNSPort {
			dns := layers.DNS{}
			if err := dns.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err == nil {
				answers := append(dns.Answers, dns.Additionals...)
				answers = append(answers, dns.Authorities...)

				for _, answer := range answers {
					switch answer.Type {
					case layers.DNSTypePTR:
					case layers.DNSTypeA:
					case layers.DNSTypeAAAA:
						meta["mdns:hostname"] = string(answer.Name)

					case layers.DNSTypeTXT:
						for _, raw := range answer.TXTs {
							if value := string(raw); strings.Contains(value, "=") {
								parts := strings.SplitN(value, "=", 2)
								meta["mdns:"+str.Trim(parts[0])] = str.Trim(parts[1])
							}
						}
					}
				}
			}
		}
	}

	if meta != nil && len(meta) > 0 {
		return meta
	}
	return nil
}

func NewMDNSProbe(from net.IP, from_hw net.HardwareAddr) (error, []byte) {
	eth := layers.Ethernet{
		SrcMAC:       from_hw,
		DstMAC:       MDNSDestMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4 := layers.IPv4{
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		TTL:      64,
		SrcIP:    from,
		DstIP:    MDNSDestIP,
	}

	udp := layers.UDP{
		SrcPort: layers.UDPPort(12345),
		DstPort: layers.UDPPort(MDNSPort),
	}

	dns := layers.DNS{
		ID:     1,
		RD:     true,
		OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte("_services._dns-sd._udp.local"),
				Type:  layers.DNSTypePTR,
				Class: layers.DNSClassIN,
			},
		},
	}

	if err := udp.SetNetworkLayerForChecksum(&ip4); err != nil {
		return err, nil
	}

	return Serialize(&eth, &ip4, &udp, &dns)
}
