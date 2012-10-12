import dpkt
import utils
from output import out
from BaseModule import BaseModule

class arp(BaseModule):
    def getAddress(self, targetip):
	address = self.config['address'].get(targetip) or self.config.get("default")
	if address == "":
	    return utils.get_mac(self.interface[0])

	if not address or address == "none":
	    return None
	return address

    # Should be an ARP Request
    def condition(self, packet):
	# Should be an ARP packet
	if packet.type != dpkt.ethernet.ETH_TYPE_ARP:
	    return False

	# Check that ARP type == Request
	if packet.data.op != dpkt.arp.ARP_OP_REQUEST:
	    return False

	targetip = utils.bin_to_ip(packet.data.tpa) 
	srcip = utils.bin_to_ip(packet.data.spa) 
	
	out.verbose("%s: Request for %s from %s" % (self.getName(), targetip, srcip)) 
	return True

    # Reply with an ARP response
    def action(self, packet):
	ifname = self.interface[0]
	targetip = utils.bin_to_ip(packet.data.tpa) 
	srcip = utils.bin_to_ip(packet.data.spa) 
	
	# Determine what mac address to use
	targetmac = self.getAddress(targetip)
	if not targetmac:
	    return False

	# Ethernet: 
	# We set source address as destination
	packet.dst = packet.src
	# And we set source address as our address
	packet.src = utils.mac_to_bin(targetmac)
	# ARP:
	# change OP to ARP Reply
	packet.data.op = dpkt.arp.ARP_OP_REPLY
	# Set target mac as sender mac
	packet.data.tha = packet.data.sha
	# Flip target IP and sender IP
	packet.data.tpa, packet.data.spa= packet.data.spa, packet.data.tpa
	# Set sender mac as our own mac
	packet.data.sha = utils.mac_to_bin(targetmac)

	# Time to send!
	utils.send_raw(ifname, str(packet))
	# Log action
	out.verbose("%s module: ARP response to %s: %s at %s " % (self.getName(), srcip, targetip, targetmac))
	return True
