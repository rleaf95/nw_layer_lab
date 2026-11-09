import struct, socket

def convert_to_mac(byte):
  return ':'.join(format(b, '02x') for b in byte)

def ethernet_header(packet):
  eth_header = packet[:14]
  eth_header = struct.unpack('!6s6sH', eth_header)
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
    "Version": version,
    "IHL": ihl,
    "Total length": total_Length,
    "TTL": ttl,
    "Protocol": protocol,
    "Checksum": checksum,
    "Source IP": src_ip,
    "Destination IP": dest_ip
  }
  remaining_packet = packet[ihl * 4:]
  return ip_info, remaining_packet


def arp_header(packet):
  arp_header = packet[:28]
  arp_header = struct.unpack('!HHBBH6s4s6s4s', arp_header)
  hardware_type = arp_header[0]
  protocol_type = arp_header[1]
  opcode = arp_header[4]
  src_mac = convert_to_mac(arp_header[5])
  src_ip = socket.inet_ntoa(arp_header[6])
  dest_mac = convert_to_mac(arp_header[7])
  dest_ip = socket.inet_ntoa(arp_header[8])
  ip_info = {
    "Hardware Type": hardware_type,
    "Protocol": protocol_type,
    "Opcode": opcode,
    "Source MACaddress": src_mac,
    "Source IP": src_ip,
    "Destination MACaddress": dest_mac,
    "Destination IP": dest_ip
  }
  remaining_packet = packet[28:]
  return ip_info, remaining_packet

def icmp_message(packet):
  icmp_header = packet[:8]
  icmp_header = struct.unpack('!BBH4s', icmp_header)
  icmp_type = icmp_header[0]
  code = icmp_header[1]
  checksum = icmp_header[2]
  
  if icmp_type == 0:
    icmp_type_str = "0: Echo Reply"
  elif icmp_type == 3:
    icmp_type_str = "3: Destination Unreachable"
  elif icmp_type == 8:
    icmp_type_str = "8: Echo Request"
  else: 
    icmp_type_str = f"{icmp_type}: Unknown ICMP Type"

  icmp_info = {
    "ICMP Type": icmp_type_str,
    "Code": code,
    "Checksum": checksum,
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

  urg_flag = (flags & 0x20) >> 5
  ack_flag = (flags & 0x10) >> 4
  psh_flag = (flags & 0x08) >> 3
  rst_flag = (flags & 0x04) >> 2
  syn_flag = (flags & 0x02) >> 1
  fin_flag = flags & 0x01

  tcp_info = {
    "Source Port": src_port,
    "Destination Port": dest_port,
    "Sequence Number": sequence_number,
    "Acknowledgment Number": acknowledgment_number,
    "SYN": syn_flag,
    "ACK": ack_flag,
    "FIN": fin_flag,
    "RST": rst_flag,
    "URG": urg_flag,
    "PSH": psh_flag,
    "Window Size": window_size,
    "Checksum": checksum
  }
  
  data_offset = (data_offset_reserved >> 4) * 4
  remaining_packet = packet[data_offset:]
  return tcp_info, remaining_packet

def udp_header(packet):
  udp_header = packet[:8]
  udp_header = struct.unpack('!HHHH', udp_header)
  udp_info = {
    "Source Port": udp_header[0],
    "Destination Port": udp_header[1],
    "Length": udp_header[2],
    "Checksum": udp_header[3]
  }
  remaining_packet = packet[8:]
  return udp_info, remaining_packet
