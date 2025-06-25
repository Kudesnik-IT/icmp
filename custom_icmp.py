import socket
import struct
import os
import sys
import time
from ctypes import *

# --- Константы ---
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

# --- Структуры ---
class IP(Structure):
    _fields_ = [
        ("ihl", c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos", c_ubyte),
        ("len", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("protocol", c_ubyte),
        ("checksum", c_ushort),
        ("src", c_uint32),
        ("dst", c_uint32),
    ]

class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("identifier", c_ushort),
        ("sequence", c_ushort),
    ]

# --- Утилиты ---
def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        part = data[i] + (data[i+1] << 8) if i+1 < len(data) else data[i]
        s += part
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def ip2bin(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def create_icmp_packet(ident, seq):
    icmp = ICMP(type=ICMP_ECHO_REQUEST, code=0, checksum=0,
                identifier=socket.htons(ident), sequence=socket.htons(seq))
    packet = bytes(icmp)
    icmp.checksum = socket.htons(checksum(packet))
    return bytes(icmp)

def create_ip_header(src_ip, dst_ip):
    ip = IP(
        ihl=5, version=4, tos=0, len=20+8,
        id=os.getpid(), offset=0,
        ttl=64, protocol=socket.IPPROTO_ICMP,
        checksum=0,
        src=ip2bin(src_ip),
        dst=ip2bin(dst_ip)
    )
    ip.checksum = socket.htons(checksum(bytes(ip)))
    return bytes(ip)

def send_icmp_raw(src_ip, dst_ip, ident, seq):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    ip_header = create_ip_header(src_ip, dst_ip)
    icmp_packet = create_icmp_packet(ident, seq)
    packet = ip_header + icmp_packet
    sock.sendto(packet, (dst_ip, 0))
    return time.time()

def sniff_reply(interface, fake_src_ip, ident, seq, timeout=5):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface, 0))
    sock.settimeout(timeout)

    try:
        while True:
            packet = sock.recv(65535)
            if len(packet) < 42:
                continue

            eth_proto = struct.unpack('!H', packet[12:14])[0]
            if eth_proto != 0x0800:
                continue  # Не IPv4

            ip_header = packet[14:34]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            protocol = iph[6]
            if protocol != 1:
                continue  # Не ICMP

            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])

            icmp_header = packet[34:42]
            icmp_type, code, checksum_recv, recv_id, recv_seq = struct.unpack('!BBHHH', icmp_header)

            # Проверка на нужный Echo Reply
            if icmp_type == ICMP_ECHO_REPLY and dst_ip == fake_src_ip:
                if recv_id == socket.htons(ident) and recv_seq == socket.htons(seq):
                    return time.time()
    except socket.timeout:
        return None

# --- Точка входа ---
def main():
    if os.geteuid() != 0:
        print("Ошибка: требуется запуск от root")
        sys.exit(1)

    if len(sys.argv) != 4:
        print("Использование: sudo {} <fake_src_ip> <dst_ip> <interface>".format(sys.argv[0]))
        sys.exit(1)

    fake_src_ip = sys.argv[1]
    dst_ip = sys.argv[2]
    interface = sys.argv[3]

    ident = os.getpid() & 0xFFFF
    seq = 1

    print("Отправка ICMP-запроса от {} к {} через {}...".format(fake_src_ip, dst_ip, interface))

    send_time = send_icmp_raw(fake_src_ip, dst_ip, ident, seq)
    recv_time = sniff_reply(interface, fake_src_ip, ident, seq, timeout=5)

    if recv_time:
        rtt = (recv_time - send_time) * 1000
        print("Ответ получен! RTT: {:.3f} ms".format(rtt))

    else:
        print("Ответ не получен (возможно, пакет был проигнорирован системой)")

if __name__ == "__main__":
    main()
