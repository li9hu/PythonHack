#encoding=utf8
import threading
import time
import socket
import os
import struct
from ctypes import *
from netaddr import IPNetwork,IPAddress


class IP(Structure):
    _fields_ = [
        ("ihl",  c_ubyte, 4),
        ("version",  c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id",  c_ushort),
        ("offset",  c_ushort),
        ("tt1", c_ubyte),
        ("protocol_num",    c_ubyte),
        ("sum", c_short),
        ("src", c_uint32),
        ("dst", c_uint32)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self,  socket_buffer=None):
        self.proto_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
        self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))

        try:
            self.protocol = self.proto_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

class ICMP(Structure):
    _fields_ = [
        ("types",    c_ubyte),
        ("code",    c_ubyte),
        ("checksum",    c_ushort),
        ("unused",  c_ushort),
        ("next_hop_mtu",    c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass

host = '172.17.12.231'
subnet = "172.17.12.0/24"

magic_message = "PYTHONRULES"

def udp_sender(subnet,magic_massage):
	time.sleep(5)
	sender = socket.socket(socket.AF_INET, socke.SOCK_DGRAM)

	for ip in IPNetwork(subnet):
		try:
			sender.sendto(magic_massage,("%s" %ip,65212))
		except:
			pass

t = threading.Thread(target=udp_sender,args=(subnet,magic_message))
t.start()

if os.name =='nt':
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host,0)) #由于icmp,ip不具备端口号
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
if 1:
	while True:
		raw_buffer = sniffer.recvfrom(65535)[0]
		ip_header = IP(raw_buffer)
		print ("Potocol: %s  %s -> %s "% (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
		if ip_header.protocol == "ICMP":
			offset = ip_header.ihl * 4
			buf  = raw_buffer[offset:offset + sizeof(ICMP)]
			icmp_header = ICMP(buf)
			print "ICMP -> Type: %d Code: %d "% (icmp_header.types, icmp_header.code)
		if 3 == icmp_header.code and icmp_header.types == 3 :
			print "ok"
			if IPAdress(ip_header.src_adress) in IPNetwork(subnet):
				if raw_buffer[len(raw_buffer)-len(magic_message):] == magic_message:
					print "host UP:"%s %ip_header.src_address
else:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
