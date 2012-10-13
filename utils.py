import fcntl, socket, struct, binascii

def get_mac(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return info[18:24]

def bin_to_mac(binaddr):
    return ''.join(['%02x:' % ord(char) for char in binaddr])[:-1]

def mac_to_bin(macaddr):
    return binascii.unhexlify(macaddr.replace(':',''))

def send_raw(ifname, data):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((ifname, 0))
    s.send(data)
    s.close()

def bin_to_ip(binip):
    return socket.inet_ntoa(binip)

def ip_to_bin(ipaddr):
    return socket.inet_aton(ipaddr)

def ip6_to_bin(ipaddr):
    return socket.inet_pton(socket.AF_INET6, ipaddr)

def bin_to_ip6(binip):
    return socket.inet_ntop(socket.AF_INET6, binip)

def get_iface_bcast(iface):
    for ifaceadd in iface[2]:
	if ifaceadd[2].count(".") == 3:
	    return ifaceadd[2]
    return False
