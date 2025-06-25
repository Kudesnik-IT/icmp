import socket
import struct

def mac_addr(mac_bytes):
    return ':'.join('%02x' % b for b in mac_bytes)

def main():
    interface = "eth0"  # Замени на свой интерфейс

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sock.bind((interface, 0))

    print("Сниффер ICMP на интерфейсе {}...\n".format(interface))

    while True:
        raw_packet = sock.recv(65535)

        eth_header = raw_packet[:14]
        eth = struct.unpack('!6s6sH', eth_header)
        eth_proto = eth[2]

        if eth_proto != 0x0800:
            continue  # не IPv4

        src_mac = mac_addr(eth[1])
        dst_mac = mac_addr(eth[0])

        ip_header = raw_packet[14:34]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        protocol = iph[6]
        if protocol != 1:
            continue  # не ICMP

        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        icmp_header = raw_packet[34:38]
        icmp_type, icmp_code = struct.unpack('!BB', icmp_header[:2])

        print("[ICMP] {} → {} | Type={} Code={} | MAC {} → {}".format(
            src_ip, dst_ip, icmp_type, icmp_code, src_mac, dst_mac
        ))

if __name__ == "__main__":
    main()
