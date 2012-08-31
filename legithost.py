#! /usr/bin/env python

import imp
import os
import argparse
from inspect import getmembers
from output import out
from utils import ip_to_bin, get_mac

try:
    import pcap
except:
    out.error("pylibpcap not found.") 
    out.error("$sudo pip install pylibpcap.")
    out.error("Exiting.")
    exit()

try:
    import dpkt
except:
    out.error("dpkt not found.") 
    out.error("$sudo pip install dpkt.")
    out.error("Exiting.")
    exit()

class LegitHost:
    def __init__(self, ifacename, modules):
	self.mod_dir = 'modules'
	self.modules = list()
	self.interface = None
	# Get interface to use
	for iface in pcap.findalldevs():
	    if ifacename == iface[0]:
		self.interface = iface
		break
	if not self.interface:
	    out.error("Can't find %s interface. Priveleges ?" % ifacename)
	    self.stop()
	# Load modules
	self.loadModules(modules)

    def findModules(self):
	modlist = [x for x in os.listdir(self.mod_dir) if x[-3:] == '.py' and x[0] != '_']
	# Remove the trailing .py
	return [x[:-3] for x in modlist]

    def loadModules(self,modules):
	out.debug("Started loading modules", 2)
	# If no modules specified through command-line args, import
	# all modules in modules directory.
	if not modules:
	    modules = self.findModules()
	for module in modules:
	    self.loadModule(module)
	out.debug("Finished loading modules", 2)

    def loadModule(self, name):
	try:
	    f, pathname, desc = imp.find_module(name, [self.mod_dir])
	except ImportError:
	    out.error("Couldn't find %s module." % name)
	    self.stop()
	lm = imp.load_source(name, pathname)
	module = [x for x in getmembers(lm) if x[0] == name][0][1]
	out.debug("loaded module %s" % name, 0)
	self.addModule(module)

    # We add and instance of the module to the list of modules (instances)
    def addModule(self, module):
	self.modules.append(module(self.interface))

    def startListener(self):
	p = pcap.pcapObject()
	p.open_live(self.getInterfaceName(), 1600, 0, 100)
	out.verbose("legitHost listener started")
	try:
	    while True:
		p.dispatch(1, self.handlePackets)
	except KeyboardInterrupt:
	    out.error("Got keyboard interrupt.")
	    self.stop()

    def getInterfaceName(self):
	return self.interface[0]

    def stop(self):
	# Anything to clean before exiting
	out.verbose("Exiting.")
	exit()

    # Returns a structured packet
    def parseData(self, data):
	packet = dpkt.ethernet.Ethernet(data)
	# Skip packets sent from our machine
	if packet.dst == get_mac(self.interface[0]):
		return None
	# ARP
	if packet.type == dpkt.ethernet.ETH_TYPE_ARP:
	    packet.data = dpkt.arp.ARP(str(packet.data))
	# IPv4
	elif packet.type == dpkt.ethernet.ETH_TYPE_IP:
	    packet.data = dpkt.ip.IP(str(packet.data))
	    # UDP
	    if packet.data.p == dpkt.ip.IP_PROTO_UDP:
		packet.data.data = dpkt.udp.UDP(str(packet.data.data))
		# LLMNR (224.0.0.252:5355), same packet format as DNS
		if packet.data.dst == ip_to_bin("224.0.0.252") and packet.data.data.dport == 5355:
		    packet.data.data.data = dpkt.dns.DNS(str(packet.data.data.data))
	    # TCP
	    elif packet.data.p == dpkt.ip.IP_PROTO_TCP:
		packet.data.data = dpkt.tcp.TCP(str(packet.data.data))

	return packet

    def handlePackets(self, pktlen, data, timestamp):
	# First, parse the packet
	packet = self.parseData(data)
	if not packet:
	    return False

	# Then send it for each module's condition
	for module in self.modules:
	    if module.condition(packet):
		out.debug("%s module accepted new packet." % module.getName(), 1)
		# TODO Dispatch to another thread
		module.action(packet)

    def run(self):
	# Listen for packets
	self.startListener()

# Build configuration from commmand line parameters
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', dest='interface', type=str, nargs=1, help='Network interface to use.', required=True)
    parser.add_argument('-d', dest='debug', type=int, nargs=1, help='Debug level')
    parser.add_argument('-m', dest='module', type=str, nargs='+', help='Modules list')

    options = parser.parse_args()
    # Set debug level
    out.setLevel(0)
    if options.debug:
	out.setLevel(options.debug[0])

    legit_host = LegitHost(options.interface[0], options.module)
    legit_host.run()
