import socket
import os
import struct
from ctypes import *


# IP header
class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32),
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # map protocol constants to ther ascii names
        self._protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        #
        self.hlen = self.ihl * 4

        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))

        # human readable protocol
        try:
            self.protocol = self._protocol_map[self.protocol_num]
        except KeyError:
            self.protocol = str(self.protocol_num)


class TCP(Structure):
    _fields_ = [
        ("src", c_ushort),
        ("dst", c_ushort),
        ("seq", c_uint32),
        ("ack", c_uint32),
        ("offset", c_ubyte, 4),
        ("res", c_ubyte, 4),
        ("control", c_ubyte),
        ("wsize", c_ushort),
        ("csum", c_ushort),
        ("urgent", c_ushort)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        pass


class Packet:
    def __init__(self, socket_buffer):
        self.ip_header = IP(socket_buffer[:20])
        self.tcp_header = TCP(socket_buffer[self.ip_header.ihl:self.ip_header.ihl + 20])
        self._hsize = self.ip_header.hlen + self.tcp_header.offset * 4
        self.data = socket_buffer[self._hsize:]

    def __str__(self):
        return "Version: {} IP Header Length: {} Protocol: {} Total Length: {} TTL: {}\n" \
               "Source IP: {} Source Port: {} Destination IP: {} Destination Port: {}\n" \
               "Sequence Number: {} Acknowledment: {}\n" \
               "Data: {}\n\n".format(
                    self.ip_header.version,
                    self.ip_header.hlen,
                    self.ip_header.protocol,
                    self.ip_header.len,
                    self.ip_header.ttl,
                    self.ip_header.src_address,
                    self.tcp_header.src,
                    self.ip_header.dst_address,
                    self.tcp_header.dst,
                    self.tcp_header.seq,
                    self.tcp_header.ack,
                    str(self.data, encoding="latin1")
                )


# create a raw socket and bind it to the public interface
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP  # sniff all incoming IP packets, regardless of the protocol
else:
    socket_protocol = socket.IPPROTO_TCP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind(('', 5555))
# include the IP header in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# if we're listening on Windows, set the nic to promiscous mode
if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

try:
    while True:
        # read packet bytes
        raw_buffer = sniffer.recvfrom(65565)[0]  # returns (bytes, address)
        packet = Packet(raw_buffer)
        print(packet)

# handle CTRL-C
except KeyboardInterrupt:
    # if we're on Windows, turn promuscous mode off
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
