import socket
import struct

def convert_to_hex(byte, Mac=True):
  return ':'.join(format(b, '02x') for b in byte)

def ethernet_header(packet):
  eth_header = packet[:14]
  eth_header = struct.unpack('!6s6sH', eth_header)
  # Preamble is removed at the hardware level.
  dest_addr = convert_to_hex(eth_header[0])
  src_addr = convert_to_hex(eth_header[1])
  protocol = eth_header[2]
  return dest_addr, src_addr, protocol

def ip_header(packet):
  ip_header = packet[14:34]
  ip_header = struct.unpack('!BBHHHBBH4s4s', ip_header)
  version, ihl = ip_header[0] >> 4, ip_header[0] & 0xF
  total_Length = ip_header[2]
  ttl = ip_header[5]
  protocol = ip_header[6]
  checksum = ip_header[7]
  src_ip = socket.inet_ntoa(ip_header[8])
  dest_ip = socket.inet_ntoa(ip_header[9])

  print(f"IP Header: {ip_header}")
  print(f"Version: {version}, IHL: {ihl}")
  print(f"Total Length: {total_Length}")
  print(f"Time to Live: {ttl}")
  print(f"Protocol: {protocol}")
  print(f"Checksum: {checksum}")
  print(f"Source IP: {src_ip}, Destination IP: {dest_ip}")
  return ip_header

def run_packet_sniffer():
  print("Launching the sniffer.....")
  try:
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
  except PermissionError:
    print("[-] Error: Root privileges are required to open a Raw Socket.")
    return

  print("==================================================")
  print("     PACKET SNIFFER ACTIVE                        ")
  print("==================================================")

  while True:
    packet, _ = raw_socket.recvfrom(65565)
    print(f"Packet received: {packet}")
    dest_addr, src_addr, protocol = ethernet_header(packet)
    print(f"Destination Address: {dest_addr}, Source Address: {src_addr}, Protocol: {protocol}")
    if protocol == 0x0800:
      header = ip_header(packet)
    elif protocol == 0x0806:
      # header = ip_header(packet)
      print("ARP packet detected.")
    else:
      print(f"Unknown protocol: {protocol}")

    # ip_header = ip_header(packet)  # Uncomment this line to process the IP header
    # ip_header = ip_header(packet)