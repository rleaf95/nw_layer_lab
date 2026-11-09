import struct, socket, sys, os
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)
from shares.packet_creation import *
from shares.packet_dissection import *

INTERFACE = sys.argv[1] if len(sys.argv) > 1 else "eth0"


def create_packet(src_ip, dst_ip, src_port, dst_port, seq_num):
  
  eth_header = creat_eth_header(dst_ip, INTERFACE)
  ip_header = create_ip_header(src_ip, dst_ip)
  ack_num = 0
  tcp_header_no_cks = create_tcp_header(src_port, dst_port, seq_num, ack_num)
  tcp_check = create_tcp_check(src_ip, dst_ip, tcp_header_no_cks)
  final_tcp_header = create_tcp_header(src_port, dst_port, seq_num, ack_num, tcp_check)

  return eth_header + ip_header + final_tcp_header
  

def create_ack_packet(src_ip, dst_ip, src_port, dst_port, client_seq, server_seq, payload=None):
  eth_header = creat_eth_header(dst_ip, INTERFACE)
  ip_header = create_ip_header(src_ip, dst_ip, payload)
  seq_num = client_seq + 1 
  # server_seq_dec = struct.unpack("!L", server_seq)[0]
  ack_num = server_seq + 1

  tcp_header_no_cks = create_tcp_header(src_port, dst_port, seq_num, ack_num, False, True, payload)
  tcp_check = create_tcp_check(src_ip, dst_ip, tcp_header_no_cks)
  final_tcp_header = create_tcp_header(src_port, dst_port, seq_num, ack_num, tcp_check, True)

  packet = eth_header + ip_header + final_tcp_header
  confirm_row = packet[42:46]
  confirm = struct.unpack("!L", confirm_row)[0]
  if payload:
    return eth_header + ip_header + final_tcp_header + payload
  return eth_header + ip_header + final_tcp_header

def listen(s):
  s.settimeout(15.0)
  while True:
    try:
      raw_data, _ = s.recvfrom(65565)
      _, src_addr, _, eth_remain = ethernet_header(raw_data)
      ip_header, ip_remain = ipv4_header(eth_remain)
      if ip_header['Protocol'] == 6:
        parsed_tcp_header, tcp_remian = parse_tcp_header(ip_remain)
        flags = {
          "SYN": parsed_tcp_header["SYN"],
          "ACK": parsed_tcp_header["ACK"],
          "FIN": parsed_tcp_header["FIN"],
          "RST": parsed_tcp_header["RST"],
          "URG": parsed_tcp_header["URG"],
          "PSH": parsed_tcp_header["PSH"],
        }
        return parsed_tcp_header["Sequence Number"], flags
      else:
        continue
    except socket.timeout:
      print("[-] Timeout")
      return None, None
    except Exception as e:
      print(f"[-] Error during listening/receiving: {e}")
      sys.exit(1)
    


def main():
  src_ip = socket.gethostbyname('client-node')
  try:
    dst_ip = socket.gethostbyname("server-node")
  except socket.gaierror:
    print('[-] Server not found')

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

  server_seq, flags = listen(s)
  if flags is None:
    print("[-] No responce received")
    sys.exit(1)

  if flags.get("SYN") == 1 and flags.get("ACK") == 1:
    payload = b"GET /normal-page HTTP/1.1\r\n Host: server-node\r\n\r\n"
    ack_packet = create_ack_packet(src_ip, dst_ip, src_port, dst_port, seq_num, server_seq, payload)
    try:
      s.sendto(ack_packet, (INTERFACE, 0))
      print("[+] Sent ACK packet [Connection Established]")
    except Exception as e:
      print(f"[-] Failed to send ACK packet: {e}")
      sys.exit(1)
  else:
    print(f"[-] Unknown flag: {flags}")
    sys.exit(1)

  next_server_seq, next_flags = listen(s)

  if next_server_seq != None:
    if next_flags.get("ACK") == 1 and next_flags.get("FIN") == 1:
      ack_packet = create_ack_packet(src_ip, dst_ip, src_port, dst_port, seq_num, next_server_seq)
      try:
        s.sendto(ack_packet, (INTERFACE, 0))
        print("[+] Sent ACK packet [Connection Established]")
      except Exception as e:
        print(f"[-] Failed to send ACK packet: {e}")
        sys.exit(1)
    else:
      print(f"[-] Unknown flag: {flags}")
      sys.exit(1)
    

if __name__ == "__main__":
  main()