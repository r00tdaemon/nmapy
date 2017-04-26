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
        self.len = self.len * 4

        # human readable IP addresses
        # NOTES: "<" - little eindian | "L" - unsigned long
        #   struct.pack() return a bytes object
        self.src_address = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("@I", self.dst))

        # human readable protocol
        try:
            self.protocol = self._protocol_map[self.protocol_num]
        except KeyError:
            self.protocol = str(self.protocol_num)

# create a raw socket and bind it to the public interface
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP  # sniff all incoming IP packets, regardless of the protocol
else:
    socket_protocol = socket.IPPROTO_TCP  # sniff only ICMP packets

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
        # create an IP header from the first 20 bytes if the buffer
        ip_header = IP(raw_buffer[:20])  # since raw_buffer is a bytes object (an immutable sequence
        # in range [0, 255]), the "jumps" are made byte-by-byte
        # print the detected protocol and the hosts
        print(
            "Version: {} IP Header Length: {} TOS: {} Total Length: {} TTL: {}\n"
            "Protocol: {} Source IP: {} Destination IP: {}\n\n".format(
                ip_header.version,
                ip_header.ihl,
                ip_header.tos,
                ip_header.len,
                ip_header.ttl,
                ip_header.protocol,
                ip_header.src_address,
                ip_header.dst_address
            )
        )

# handle CTRL-C
except KeyboardInterrupt:
    # if we're on Windows, turn promuscous mode off
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
