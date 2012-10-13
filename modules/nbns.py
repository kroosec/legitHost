import utils
from socket import socket, AF_INET, SOCK_DGRAM
from output import out
from BaseModule import BaseModule
from dpkt.ethernet import ETH_TYPE_IP
from dpkt.ip import IP_PROTO_UDP
from dpkt.netbios import decode_name, encode_name, NS

class nbns(BaseModule):
    def getAddress(self, name):
	# Name Query is case insensitive
	address = self.config['address'].get(name.lower()) or self.config.get("default")
	if address == "default":
	    for ifaceadd in self.interface[2]:
		if ifaceadd[0].count(".") == 3:
		    return ifaceadd[0]

	if not address or address == "none":
	    return False
	return address

    # Should be a Netbios Name Service Query to broadcast address
    def condition(self, packet):
	# Should be an IPv4 packet
	if packet.type != ETH_TYPE_IP:
	    return False

	# Should be a broadcast request
	dstip = utils.bin_to_ip(packet.data.dst)
	if dstip != utils.get_iface_bcast(self.interface) and dstip != "255.255.255.255":
	    return False

	# Should be a UDP packet
	if packet.data.p != IP_PROTO_UDP:
	    return False

	# Should be from port 137 to port 137
	if packet.data.data.dport != 137 or packet.data.data.dport != 137:
	    return False

	# Must be a Name Query
	 # bit 1 = Message is a Query
	 # bit 2-5 = Opcode: Name Query
	  # We check this so we don't reply to Registration Queries
	if packet.data.data.data.op & 0xf800 != 0:
	    return False
	out.verbose("%s: Request from %s" % (self.getName(), utils.bin_to_ip(packet.data.src)))
	out.verbose("%s: \tQueries: %s" % (self.getName(), ' '.join([decode_name(x.name).rstrip() for x in packet.data.data.data.qd])))
	return True

    # Reply with NetBios Name Service Response
    def action(self, packet):
	targetip = utils.bin_to_ip(packet.data.src)
	targetport = 137
	nbns_response = packet.data.data.data
	nbns_response.op = 0x8500
	# For each question, add an answer
	for query in nbns_response.qd:
	    name = decode_name(query.name).rstrip()
	    address = self.getAddress(name)
	    if not address:
		out.debug("%s: Skipped Query from %s for %s" % (self.getName(), targetip, name), 0)
		continue
	    answer = NS.RR()
	    answer.name = query.name # We reinsert in encoded format
	    answer.type = query.type
	    answer.cls = query.cls
	    answer.ttl = 120 # Not very long TTL
	    answer.rlen = 6
	    answer.rdata = '\x00\x00' + utils.ip_to_bin(address) # 0x0000 is flags for Unique name + B-Node
	    nbns_response.an.append(answer)
	nbns_response.qd = []

	if len(nbns_response.an) == 0:
	    return False
	# Response is a UDP packet with 137 source port and Query's IP+Port as destination
	sock = socket(AF_INET, SOCK_DGRAM)
	sock.bind(('0.0.0.0', targetport))
	sock.sendto(str(nbns_response), (targetip, packet.data.data.sport))
	sock.close()
	for answer in nbns_response.an:
	    out.verbose("%s: \tResponse: %s - %s" % (self.getName(), decode_name(answer.name).rstrip(), utils.bin_to_ip(answer.rdata[2:])))
	return True
