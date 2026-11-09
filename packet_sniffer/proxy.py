from scapy.all import Ether, IP, TCP, sendp
import socket, sys

def handle_syn_ack(dst_mac, src_mac, ip_info, transport_info, interface):
  client_ip = ip_info['Source IP']
  client_mac = dst_mac
  client_port = transport_info['Source Port']
  client_seq = transport_info["Sequence Number"]
  my_mac =  src_mac
  server_port = transport_info["Destination Port"]
  server_ip = ip_info['Destination IP']
  
  print(f"[Sniffer Log] [+] Caught SYN from {client_ip}:{client_port}")
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
  sendp(syn_ack_packet, iface=interface, verbose=False)
  print(f"[Sniffer Log] [+] Sent SYN-ACK to {client_ip}:{client_port}")

def connect_to_server(server_ip, server_port):
  server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  
  try:
    server_sock.connect((server_ip, server_port))
    print(f"[+] 【スニッファー ⇄ サーバー】 標準ソケットでの接続確立に成功しました！")
    return server_sock
      
  except socket.error as e:
    print(f"[-] サーバーへの接続に失敗しました: {e}")
    sys.exit(1)