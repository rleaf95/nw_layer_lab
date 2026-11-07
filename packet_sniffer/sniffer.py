import socket
import struct

def convert_to_mac(byte, Mac=True):
  return ':'.join(format(b, '02x') for b in byte)

def ethernet_header(packet):
  eth_header = packet[:14]
  eth_header = struct.unpack('!6s6sH', eth_header)
  # Preamble is removed at the hardware level.
  dest_addr = convert_to_mac(eth_header[0])
  src_addr = convert_to_mac(eth_header[1])
  protocol = eth_header[2]
  remaining_packet = packet[14:]

  return dest_addr, src_addr, protocol, remaining_packet

def ipv4_header(packet):
  ipv4_header = packet[:20]
  ipv4_header = struct.unpack('!BBHHHBBH4s4s', ipv4_header)
  version, ihl = ipv4_header[0] >> 4, ipv4_header[0] & 0xF
  total_Length = ipv4_header[2]
  ttl = ipv4_header[5]
  protocol = ipv4_header[6]
  checksum = ipv4_header[7]
  src_ip = socket.inet_ntoa(ipv4_header[8])
  dest_ip = socket.inet_ntoa(ipv4_header[9])
  ip_info = {
    "version": version,
    "ihl": ihl,
    "total_length": total_Length,
    "ttl": ttl,
    "protocol": protocol,
    "checksum": checksum,
    "src_ip": src_ip,
    "dest_ip": dest_ip
  }
  remaining_packet = packet[ihl * 4:]
  return ip_info, remaining_packet

def arp_header(packet):
  arp_header = packet[:28]
  arp_header = struct.unpack('!HHBBH6s4s6s4s', arp_header)
  hardware_type = arp_header[0]
  protocol_type = arp_header[1]
  hardware_size = arp_header[2] #Lengh of MAC address - 6
  protocol_size = arp_header[3] #Length of IP address - 4
  opcode = arp_header[4]
  src_mac = convert_to_mac(arp_header[5])
  src_ip = socket.inet_ntoa(arp_header[6])
  dest_mac = convert_to_mac(arp_header[7])
  dest_ip = socket.inet_ntoa(arp_header[8])
  ip_info = {
    "hardware_type": hardware_type,
    "protocol_type": protocol_type,
    "opcode": opcode,
    "src_mac": src_mac,
    "src_ip": src_ip,
    "dest_mac": dest_mac,
    "dest_ip": dest_ip
  }
  remaining_packet = packet[28:]
  return ip_info, remaining_packet

def icmp_message(packet):
  icmp_header = packet[:8]
  icmp_header = struct.unpack('!BBH4s', icmp_header)
  icmp_type = icmp_header[0]
  code = icmp_header[1]
  checksum = icmp_header[2]
  rest = icmp_header[3]
  
  if icmp_type == 0:
    icmp_type = "0: Echo Reply"
  elif icmp_type == 3:
    icmp_type = "3: Destination Unreachable"
  elif icmp_type == 8:
    icmp_type = "8: Echo Request"
  else: 
    icmp_type = f"{icmp_type}: Unknown ICMP Type"

  print(f"ICMP Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
  icmp_info = {
    "icmp_type": icmp_type,
    "code": code,
    "checksum": checksum,
  }
  remaining_packet = packet[8:]
  return icmp_info, remaining_packet

def tcp_header(packet):
  tcp_header = packet[:20]
  tcp_header = struct.unpack('!HHLLBBHHH', tcp_header)

  src_port = tcp_header[0]
  dest_port = tcp_header[1]
  sequence_number = tcp_header[2]
  acknowledgment_number = tcp_header[3]
  data_offset_reserved = tcp_header[4]
  flags = tcp_header[5]
  window_size = tcp_header[6]
  checksum = tcp_header[7]
  urgent_pointer = tcp_header[8]

  # Extract individual flags from the flags byte
  urg_flag = (flags & 0x20) >> 5
  ack_flag = (flags & 0x10) >> 4
  psh_flag = (flags & 0x08) >> 3
  rst_flag = (flags & 0x04) >> 2
  syn_flag = (flags & 0x02) >> 1
  fin_flag = flags & 0x01

  tcp_info = {
    "src_port": src_port,
    "dest_port": dest_port,
    "sequence_number": sequence_number,
    "acknowledgment_number": acknowledgment_number,
    "data_offset_reserved": data_offset_reserved,
    "urg_flag": urg_flag,
    "ack_flag": ack_flag,
    "psh_flag": psh_flag,
    "rst_flag": rst_flag,
    "syn_flag": syn_flag,
    "fin_flag": fin_flag,
    "window_size": window_size,
    "checksum": checksum,
    "urgent_pointer": urgent_pointer
  }
  
  remaining_packet = packet[(data_offset_reserved >> 4) * 4:]
  
  return tcp_info, remaining_packet

def udp_header(packet):
  udp_header = packet[:8]
  udp_header = struct.unpack('!HHHH', udp_header)

  src_port = udp_header[0]
  dest_port = udp_header[1]
  length = udp_header[2]
  checksum = udp_header[3]

  udp_info = {
    "src_port": src_port,
    "dest_port": dest_port,
    "length": length,
    "checksum": checksum
  }

  remaining_packet = packet[8:]

  return udp_info, remaining_packet

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
    print("==================================================\n")
    packet, _ = raw_socket.recvfrom(65565)
    print(f"Packet received: {packet}")

    # Extract Ethernet header information
    dest_addr, src_addr, protocol, ip_payload = ethernet_header(packet)
    print(f"Destination Address: {dest_addr}, Source Address: {src_addr}, Protocol: {protocol}")

    # Extract IP header information based on the protocol
    if protocol == 0x0800:
      ip_info, remaining_packet = ipv4_header(ip_payload)
    elif protocol == 0x0806:
      ip_info, remaining_packet = arp_header(ip_payload)
      print("ARP packet detected.")
    else:
      ip_info = None
      remaining_packet = None
      print(f"Unknown protocol: {protocol}")

    if ip_info:
      for key, value in ip_info.items():
        print(f"{key}: {value}")

    if protocol == 0x0800: # need to add ipv6 later
      if ip_info.get("protocol") == 1:  #ICMP protocol
        info, transport_payload = icmp_message(remaining_packet)
      elif ip_info.get("protocol") == 6:  #TCP protocol
        info, transport_payload = tcp_header(remaining_packet)
      elif ip_info.get("protocol") == 17:  #UDP protocol
        info, transport_payload = udp_header(remaining_packet)
      else:
        print("Unknown protocol detected.")

      if info:
        for key, value in info.items():
          print(f"{key}: {value}")

        if len(transport_payload) > 0:
          print(f"--- Payload (Length: {len(transport_payload)} bytes) ---")
          try:
            readable_text = transport_payload.decode('utf-8', errors='ignore')
            print(f'Readable Text: {readable_text.strip()}')
          except Exception as e:
              print("(Binary Data)")
          print('\n')