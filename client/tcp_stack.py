import struct, socket, sys, os
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)
from shares.packet_creation import *

INTERFACE = sys.argv[1] if len(sys.argv) > 1 else "eth0"


def create_packet(src_ip, dst_ip, src_port, dst_port, seq_num):
  
  eth_header = creat_eth_header(dst_ip, INTERFACE)
  ip_header = create_ip_header(src_ip, dst_ip)
  ack_num = 0
  tcp_header_no_cks = create_tcp_header(src_port, dst_port, seq_num, ack_num)
  tcp_check = create_tcp_check(src_ip, dst_ip, tcp_header_no_cks)
  final_tcp_header = create_tcp_header(src_port, dst_port, seq_num, ack_num, tcp_check)
  return eth_header + ip_header + final_tcp_header
  

def create_ack_packet(src_ip, dst_ip, src_port, dst_port, client_seq, server_seq):
  eth_header = creat_eth_header(dst_ip, INTERFACE)
  ip_header = create_ip_header(src_ip, dst_ip)
  seq_num = client_seq + 1 
  server_seq_dec = struct.unpack("!L", server_seq)[0]
  ack_num = server_seq_dec + 1
  tcp_header_no_cks = create_tcp_header(src_port, dst_port, seq_num, ack_num, True)
  tcp_check = create_tcp_check(src_ip, dst_ip, tcp_header_no_cks)
  final_tcp_header = create_tcp_header(src_port, dst_port, seq_num, ack_num, tcp_check, True)

  return eth_header + ip_header + final_tcp_header

def listen_for_ack(s, port, mac):
  s.settimeout(3.0)
  while True:
    try:
      raw_data, _ = s.recvfrom(65565)
      if len(raw_data) < 34:
        continue
      src_mac_raw = raw_data[6:12]
      ihl = raw_data[14]& 0xF 
      ip_header_len = ihl * 4
      tcp_start = 14 + ip_header_len
      if len(raw_data) < tcp_start + 20:
        continue
      src_port = struct.unpack("!H", raw_data[34:36])[0]
      server_seq = raw_data[tcp_start + 4 : tcp_start + 8]
      tcp_flag = raw_data[tcp_start + 13]
      if tcp_flag != 0x12:
        continue
      if src_mac_raw == mac and src_port == port:
        print('[+] Caught SYN-ACK packet')
        return True, server_seq
      else:
        continue
      
    except socket.timeout:
      print("[-] Timeout: No SYN-ACK received within 3 seconds.")
      break
    except Exception as e:
      print(f"[-] Error during receiving: {e}")
      break



def main():
  src_ip = socket.gethostbyname('client-node')
  try:
    dst_ip = socket.gethostbyname("server-node")
  except socket.gaierror:
    print('Server not found')

  src_port = 54321
  dst_port = 80
  seq_num = 1000

  try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
  except PermissionError:
    print("[-] Error: permission error")
    sys.exit(1)

  #-------------------------------
  # Create SYN packet and send it
  #-------------------------------
  packet = create_packet(src_ip, dst_ip, src_port, dst_port, seq_num)
  try:
    s.sendto(packet, (INTERFACE, 0))
    print("[+] Sent SYN packet and Wait for ACK")
  except Exception as e:
    print(f"[-] Failed to send SYN packet: {e}")
    sys.exit(1)

  #-------------------------------
  # Wait for SYN-ACK packet
  #-------------------------------
  try:
    response, server_seq = listen_for_ack(s, dst_port, get_dst_mac(dst_ip))
  except Exception as e:
    print(f"[-] Error during listening/receiving: {e}")
    sys.exit(1)

  #-------------------------------
  #W Create ACK packet and send it
  #-------------------------------
  if response:
    ack_packet = create_ack_packet(src_ip, dst_ip, src_port, dst_port, seq_num, server_seq)
    try:
      s.sendto(ack_packet, (INTERFACE, 0))
      print("[+] Sent ACK packet [Connection Established]")
    except Exception as e:
      print(f"[-] Failed to send ACK packet: {e}")
      sys.exit(1)
  

if __name__ == "__main__":
  main()