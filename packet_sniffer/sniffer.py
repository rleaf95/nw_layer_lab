import socket, struct, datetime
from packet_sniffer.proxy import *
from shares.packet_dissection import *
from shares.packet_creation import get_dst_mac


socket_to_client = {}

def log_packet(message, is_tcp):
  timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  log_line = f"[{timestamp}] {message}\n"
  with open("sniffer.log", "a") as f:
    f.write(log_line)
  if is_tcp:
    with open("sniffer_tcp.log", "a") as f:
      f.write(log_line)


def run_packet_sniffer(interface, my_mac, ip_dist, logger):
  my_ip = socket.gethostbyname('sniffer-node')
  try:
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
  except PermissionError:
    print("[-] Error: Root privileges are required to open a Raw Socket.")
    return

  while True:
    packet, _ = raw_socket.recvfrom(65565)

    ip_details = ""
    transport_detail = ""
    transport_payload = b""
    readable_text = ""
    is_tcp = False

    dest_addr, src_addr, protocol, ip_payload = ethernet_header(packet)

    ip_info = None
    remaining_packet = None
    
    if protocol == 0x0800: # IPv4
      ip_info, remaining_packet = ipv4_header(ip_payload)
      for key, value in ip_info.items():
        ip_details += f"  {key}: {value}"

      proto_num = ip_info.get("Protocol")
      if proto_num == 1:   # ICMP
        transport_info, transport_payload = icmp_message(remaining_packet)
      elif proto_num == 6:  # TCP
        transport_info, transport_payload = parse_tcp_header(remaining_packet)
        is_tcp = True
        src_port = transport_info['Source Port']
        dst_port = transport_info['Destination Port']

        if src_port == 9999 or dst_port == 9999:
          continue

        if ip_info['Destination IP'] != my_ip and dest_addr == my_mac:
          if transport_info['SYN'] == 1 and transport_info['ACK'] == 0:
            ip_dist = handle_syn_ack(src_addr, dest_addr, ip_info, transport_info, interface, ip_dist, logger)
            server_ip = ip_info['Destination IP']
            server_port = transport_info['Destination Port']
            ip_dist = connect_to_server(server_ip, server_port, ip_dist, logger)
            socket_to_client[server_port] = ip_info['Source IP']
          elif transport_info['PSH'] == 1:
            src_ip = ip_info['Source IP']
            decode_payload = transport_payload.decode('utf-8')
            logger.info(f'[+] Packet received from {src_ip} with payload:\n[Payload]\n{decode_payload}')
            dst_ip = ip_info["Destination IP"]
            dst_mac = ip_dist[dst_ip]['mac']
            target_socket = ip_dist[dst_ip]['socket']
            if target_socket != None:
              handle_transfer_packet(interface, logger, dst_ip, dst_mac, target_socket, transport_payload)
            else:
              print(f'[-] Socket for {dst_ip} is unknown' )
        elif ip_info['Destination IP'] == my_ip and transport_info['PSH']:
          source_port = transport_info['Source Port'] 
          dst_ip = socket_to_client[source_port]
          src_ip = ip_info['Source IP']
          dst_mac = ip_dist[dst_ip]['mac']
          target_socket = ip_dist[dst_ip]['socket']
          handle_transfer_packet(interface, logger, dst_ip, dst_mac, target_socket, transport_payload, is_client=True, src_port=source_port, ip=src_ip)
      elif proto_num == 17:
        transport_info, transport_payload = udp_header(remaining_packet)
      else:
        transport_info = {"Info": f"Other IP Protocol: {proto_num}"}
        transport_payload = remaining_packet

      for key, value in transport_info.items():
        transport_detail += f"  {key}: {value}"

    elif protocol == 0x0806: # ARP
      ip_info, remaining_packet = arp_header(ip_payload)
      for key, value in ip_info.items():
        ip_details += f"  {key}: {value}"
      transport_detail = " ARP Packet (No Transport Layer)"
    else:
      ip_details = f"  Unknown Ethernet Protocol: {hex(protocol)}"

    if len(transport_payload) > 0:
      try:
        readable_text = transport_payload.decode('utf-8', errors='ignore')
      except Exception:
        readable_text = 'Binary Data'

    message = f"""
  --- Ethernet Header ---
    Destination: {dest_addr}, Source: {src_addr}, Protocol: {hex(protocol)}
  --- IP / Network Header ---
  {ip_details}
  --- Transport Header / Details ---
  {transport_detail}
  --- Payload (Length: {len(transport_payload)} bytes) ---
  {readable_text.strip()}
--------------------------------------------------"""

    log_packet(message, is_tcp)