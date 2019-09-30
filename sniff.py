#encoding=utf8
import socket
import os
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

if os.name =='nt':
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)

sniffer.bind((host,0)) #由于icmp,ip不具备端口号
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
try:
    while True:
        raw_buffer = sniffer.recvfrom(65535)[0]
        ip_header = IP(raw_buffer)

        print ("Potocol: %s  %s -> %s "% (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
except:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
