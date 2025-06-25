import socket
import struct
import sys
import os
import time
import fcntl
from ctypes import *

# Проверка запуска от root
if os.geteuid() != 0:
    print("Ошибка: Требуются права root (sudo)")
    sys.exit(1)

# Константы
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ETH_P_ALL = 0x0003

# IP заголовок
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

# ICMP заголовок
class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("checksum", c_ushort),
        ("identifier", c_ushort),
        ("sequence", c_ushort)
    ]

def checksum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum += this_val
        count += 2
    if count_to < len(source_string):
        sum += source_string[len(source_string) - 1]
    sum = (sum >> 16) + (sum & 0xFFFF)
    sum += (sum >> 16)
    answer = ~sum & 0xFFFF
    return answer >> 8 | (answer << 8 & 0xFF00)

def ip2bin(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def create_icmp_packet(identifier=1, sequence=1):
    icmp = ICMP(
        type=ICMP_ECHO_REQUEST,
        code=0,
        checksum=0,
        identifier=socket.htons(identifier),
        sequence=socket.htons(sequence)
    )
    buf = bytes(icmp)
    icmp.checksum = socket.htons(checksum(buf))
    return bytes(icmp)

def create_ip_packet(src_ip, dst_ip):
    ip = IP(
        ihl=5,
        version=4,
        tos=0,
        len=20 + 8,
        id=54321,
        offset=0,
        ttl=255,
        protocol=socket.IPPROTO_ICMP,
        checksum=0,
        src=ip2bin(src_ip),
        dst=ip2bin(dst_ip)
    )
    ip.checksum = socket.htons(checksum(bytes(ip)))
    return bytes(ip)

def send_icmp(sock, src_ip, dst_ip, ident, seq):
    icmp_packet = create_icmp_packet(ident, seq)
    ip_packet = create_ip_packet(src_ip, dst_ip)
    packet = ip_packet + icmp_packet
    sock.sendto(packet, (dst_ip, 0))
    return time.time()

def get_mac(interface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return fcntl.ioctl(
        s.fileno(),
        0x8927,
        struct.pack('256s', interface[:15].encode())
    )[18:24]

def listen_for_reply_packet_mode(sock, dst_ip, expected_id, expected_seq, timeout=10):
    sock.settimeout(timeout)
    try:
        while True:
            packet = sock.recv(65535)
            if len(packet) < 42:
                continue

            eth_proto = struct.unpack('!H', packet[12:14])[0]
            if eth_proto != 0x0800:
                continue

            ip_header = packet[14:34]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            protocol = iph[6]
            if protocol != 1:
                continue

            src_ip_recv = socket.inet_ntoa(iph[8])
            dst_ip_recv = socket.inet_ntoa(iph[9])
            if src_ip_recv != dst_ip:
                continue

            icmph = ICMP.from_buffer_copy(packet[34:42])
            if icmph.type == ICMP_ECHO_REPLY:
                if socket.ntohs(icmph.identifier) == expected_id and socket.ntohs(icmph.sequence) == expected_seq:
                    reply_time = time.time()
                    rtt_ms = (reply_time - send_time_global) * 1000
                    return rtt_ms
    except socket.timeout:
        return None

def main():
    if len(sys.argv) != 4:
        print("Использование: sudo {} <src_ip> <dst_ip> <interface>".format(sys.argv[0]))
        sys.exit(1)

    src_ip = sys.argv[1]
    dst_ip = sys.argv[2]
    interface = sys.argv[3]

    def is_valid_ip(ip):
        parts = ip.split('.')
        return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

    if not (is_valid_ip(src_ip) and is_valid_ip(dst_ip)):
        print("Ошибка: Неверный формат IP-адреса")
        sys.exit(1)

    print("ICMP-запросы от {} к {}".format(src_ip, dst_ip))

    ident = os.getpid() & 0xFFFF
    seq = 1

    packets_sent = 0
    packets_received = 0
    total_rtt = 0.0
    min_rtt = float('inf')
    max_rtt = 0.0

    try:
        sock_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock_send.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode())

        sock_recv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        sock_recv.bind((interface, 0))

        while True:
            print("Запрос отправлен - ", end="", flush=True)
            packets_sent += 1

            global send_time_global
            send_time_global = send_icmp(sock_send, src_ip, dst_ip, ident, seq)

            result = listen_for_reply_packet_mode(sock_recv, dst_ip, ident, seq, timeout=3)

            if result is not None:
                packets_received += 1
                total_rtt += result
                min_rtt = min(min_rtt, result)
                max_rtt = max(max_rtt, result)
                print("Ответ получен - RTT: {:.3f} ms".format(result))
            else:
                print("Нет ответа")

            seq += 1
            time.sleep(1)

    except KeyboardInterrupt:
        loss = ((packets_sent - packets_received) / packets_sent) * 100 if packets_sent > 0 else 0
        avg_rtt = total_rtt / packets_received if packets_received > 0 else 0

        print("\nОстановка пользователем\n")
        print("Статистика:")
        print("  Отправлено:   {}".format(packets_sent))
        print("  Получено:     {}".format(packets_received))
        print("  Потеряно:     {} ({:.2f}%)".format(packets_sent - packets_received, loss))
        if packets_received > 0:
            print("  Минимальный RTT: {:.3f} ms".format(min_rtt))
            print("  Максимальный RTT: {:.3f} ms".format(max_rtt))
            print("  Средний RTT:     {:.3f} ms".format(avg_rtt))
        sys.exit(0)

if __name__ == "__main__":
    main()
