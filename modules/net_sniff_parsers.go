package modules

import (
	"fmt"

	"github.com/bettercap/bettercap/core"
	"github.com/bettercap/bettercap/log"
	"github.com/bettercap/bettercap/packets"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func tcpParser(ip *layers.IPv4, pkt gopacket.Packet, verbose bool) {
	tcp, tcpOk := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !tcpOk {
		log.Debug("Could not parse TCP layer, skipping packet")
		return
	}

	if sniParser(ip, pkt, tcp) {
		return
	} else if ntlmParser(ip, pkt, tcp) {
		return
	} else if httpParser(ip, pkt, tcp) {
		return
	} else if verbose {
		NewSnifferEvent(
			pkt.Metadata().Timestamp,
			"tcp",
			fmt.Sprintf("%s:%s", ip.SrcIP, vPort(tcp.SrcPort)),
			fmt.Sprintf("%s:%s", ip.DstIP, vPort(tcp.DstPort)),
			SniffData{
				"Size": len(ip.Payload),
			},
			"%s %s:%s > %s:%s %s",
			core.W(core.BG_LBLUE+core.FG_BLACK, "tcp"),
			vIP(ip.SrcIP),
			vPort(tcp.SrcPort),
			vIP(ip.DstIP),
			vPort(tcp.DstPort),
			core.Dim(fmt.Sprintf("%d bytes", len(ip.Payload))),
		).Push()
	}
}

func udpParser(ip *layers.IPv4, pkt gopacket.Packet, verbose bool) {
	udp, udpOk := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !udpOk {
		log.Debug("Could not parse UDP layer, skipping packet")
		return
	}

	if dnsParser(ip, pkt, udp) {
		return
	} else if mdnsParser(ip, pkt, udp) {
		return
	} else if krb5Parser(ip, pkt, udp) {
		return
	} else if verbose {
		NewSnifferEvent(
			pkt.Metadata().Timestamp,
			"udp",
			fmt.Sprintf("%s:%s", ip.SrcIP, vPort(udp.SrcPort)),
			fmt.Sprintf("%s:%s", ip.DstIP, vPort(udp.DstPort)),
			SniffData{
				"Size": len(ip.Payload),
			},
			"%s %s:%s > %s:%s %s",
			core.W(core.BG_DGRAY+core.FG_WHITE, "udp"),
			vIP(ip.SrcIP),
			vPort(udp.SrcPort),
			vIP(ip.DstIP),
			vPort(udp.DstPort),
			core.Dim(fmt.Sprintf("%d bytes", len(ip.Payload))),
		).Push()
	}
}

// icmpParser logs ICMPv4 events when verbose, and does nothing otherwise.
//
// A useful improvement would be to log the ICMP code
// and add meaningful interpretation of the payload based on code.
func icmpParser(ip *layers.IPv4, pkt gopacket.Packet, verbose bool) {
	if verbose {
		icmp := pkt.Layer(layers.LayerTypeICMPv4)
		layerType := icmp.LayerType().String()
		NewSnifferEvent(
			pkt.Metadata().Timestamp,
			layerType,
			vIP(ip.SrcIP),
			vIP(ip.DstIP),
			SniffData{
				"Size": len(ip.Payload),
			},
			"%s %s > %s %s",
			core.W(core.BG_DGRAY+core.FG_WHITE, layerType),
			vIP(ip.SrcIP),
			vIP(ip.DstIP),
			core.Dim(fmt.Sprintf("%d bytes", len(ip.Payload))),
		).Push()
	}
}

func unkParser(ip *layers.IPv4, pkt gopacket.Packet, verbose bool) {
	if verbose {
		NewSnifferEvent(
			pkt.Metadata().Timestamp,
			pkt.TransportLayer().LayerType().String(),
			vIP(ip.SrcIP),
			vIP(ip.DstIP),
			SniffData{
				"Size": len(ip.Payload),
			},
			"%s %s > %s %s",
			core.W(core.BG_DGRAY+core.FG_WHITE, pkt.TransportLayer().LayerType().String()),
			vIP(ip.SrcIP),
			vIP(ip.DstIP),
			core.Dim(fmt.Sprintf("%d bytes", len(ip.Payload))),
		).Push()
	}
}

func mainParser(pkt gopacket.Packet, verbose bool) bool {
	// simple networking sniffing mode?
	nlayer := pkt.NetworkLayer()
	if nlayer != nil {
		if nlayer.LayerType() != layers.LayerTypeIPv4 {
			log.Debug("Unexpected layer type %s, skipping packet.", nlayer.LayerType())
			return false
		}

		ip, ipOk := nlayer.(*layers.IPv4)
		if !ipOk {
			log.Debug("Could not extract network layer, skipping packet")
			return false
		}

		tlayer := pkt.TransportLayer()
		if tlayer == nil {
			_, icmpOk := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
			if icmpOk {
				icmpParser(ip, pkt, verbose)
				return true
			} else {
				log.Debug("Missing transport layer skipping packet.")
				return false
			}
		}

		if tlayer.LayerType() == layers.LayerTypeTCP {
			tcpParser(ip, pkt, verbose)
		} else if tlayer.LayerType() == layers.LayerTypeUDP {
			udpParser(ip, pkt, verbose)
		} else {
			unkParser(ip, pkt, verbose)
		}
		return true
	} else if ok, radiotap, dot11 := packets.Dot11Parse(pkt); ok {
		// are we sniffing in monitor mode?
		dot11Parser(radiotap, dot11, pkt, verbose)
		return true
	}
	return false
}
