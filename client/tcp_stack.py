import struct, socket, sys, subprocess
from scapy.all import srp, Ether, ARP, conf

INTERFACE = sys.argv[1] if len(sys.argv) > 1 else "eth0"

def send_broadcast(dest_ip, dest_port=80):
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  try:
    sock.sendto(b'Hello', (dest_ip, dest_port))
  except Exception as e:
    print(f"[-] Failed to trigger ARP: {e}")
  finally:
    sock.close()


def get_dst_mac(target_ip):
  try:
    with open('/proc/net/arp', 'r') as f:
      lines = f.readlines()
      for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 4:
            ip = parts[0]
            mac = parts[3]
            if ip == target_ip and mac != "00:00:00:00:00:00":
              return bytes.fromhex(mac.replace(':', ''))
    mac = send_broadcast(target_ip)
    print(mac)
    if mac and mac != "00:00:00:00:00:00":
      return bytes.fromhex(mac.replace(':', ''))
    
          
  except Exception as e:
      print(f"Failed to read ARP table: {e}")
  return None

def get_my_mac(interface="eth0"):
  try:
    with open(f"/sys/class/net/{interface}/address", "r") as f:
      mac_str = f.read().strip()
      return bytes.fromhex(mac_str.replace(":", ""))
  except Exception as e:
    print(f"Failed to get my MAC/ file name: {interface}:{e}")


def get_checksum(psh):
  s = 0
  for i in range(0, len(psh), 2):
    w = (psh[i] << 8) + (psh[i+1] if i + 1 < len(psh) else 0)
    s += w
  while s >> 16:
    s = (s & 0xffff) + (s >> 16)  
  return ~s & 0xffff

def creat_eth_header(dst_ip):
  src_mac = get_my_mac(INTERFACE)
  dst_mac = get_dst_mac(dst_ip)
  eth_proto = b'\x08\x00'
  return dst_mac + src_mac + eth_proto

def create_ip_header(src_ip, dst_ip):
  version = 4
  ihl = 5
  tos = 0
  tot_len = 20 + 20
  id = 12345
  frag = 0x4000
  ttl = 64
  protocol = 6
  checksum = 0
  version_ihl = (version << 4) + ihl
  src_ip_bytes = socket.inet_aton(src_ip)
  dst_ip_bytes = socket.inet_aton(dst_ip)

  ip_header = struct.pack(
    '!BBHHHBBH4s4s', version_ihl, tos, tot_len, id, frag, ttl, protocol, checksum, src_ip_bytes, dst_ip_bytes
  )
  return ip_header

def create_tcp_header(src_port, dst_port, seq_num, ack_num, tcp_check=False, ack=False ):
  offset = 5
  reserved = 0
  flags = 0x10 if ack else 0x02 #syn
  window = socket.htons(5840)
  checksum = 0
  urg_ptr = 0
  offset_flags = (offset << 12) | flags
  if tcp_check: 
    tcp_header = struct.pack(
      '!HHLLHHHH', src_port, dst_port, seq_num, ack_num, offset_flags, window, tcp_check, urg_ptr  
    )
  else:
    tcp_header = struct.pack(
      '!HHLLHHHH', src_port, dst_port, seq_num, ack_num, offset_flags, window, checksum, urg_ptr  
    )

  return tcp_header

def create_tcp_check(src_ip, dst_ip, tcp_header_no_cks):

  source_ip = socket.inet_aton(src_ip) 
  dest_ip = socket.inet_aton(dst_ip)
  placeholder = 0
  protocol = 6
  tcp_length = len(tcp_header_no_cks)
  pseudo_header = struct.pack('!4s4sBBH', source_ip, dest_ip, placeholder, protocol, tcp_length)  
  psh = pseudo_header +  tcp_header_no_cks
  tcp_check = get_checksum(psh)
  return tcp_check


def create_packet(src_ip, dst_ip, src_port, dst_port, seq_num):
  
  eth_header = creat_eth_header(dst_ip)
  ip_header = create_ip_header(src_ip, dst_ip)
  ack_num = 0
  tcp_header_no_cks = create_tcp_header(src_port, dst_port, seq_num, ack_num)
  tcp_check = create_tcp_check(src_ip, dst_ip, tcp_header_no_cks)
  final_tcp_header = create_tcp_header(src_port, dst_port, seq_num, ack_num, tcp_check)

  return eth_header + ip_header + final_tcp_header
  

def create_ack_packet(src_ip, dst_ip, src_port, dst_port, client_seq, server_seq):
  eth_header = creat_eth_header(dst_ip)
  ip_header = create_ip_header(src_ip, dst_ip)
  seq_num = client_seq + 1 
  server_seq_dec = struct.unpack("!L", server_seq)[0]
  ack_num = server_seq_dec + 1
  tcp_header_no_cks = create_tcp_header(src_port, dst_port, seq_num, ack_num, True)
  tcp_check = create_tcp_check(src_ip, dst_ip, tcp_header_no_cks)
  final_tcp_header = create_tcp_header(src_port, dst_port, seq_num, ack_num, tcp_check, True)

  return eth_header + ip_header + final_tcp_header

def listen_for_ack(s, port, mac):
  s.settimeout(5.0)
  while True:
    try:
      raw_data, _ = s.recvfrom(65565)
      if len(raw_data) < 34:
        continue
      src_mac_raw = raw_data[6:12]
      ihl = raw_data[14]& 0xF 
      ip_header_len = ihl * 4
      tcp_start = 14 + ip_header_len
      if len(raw_data) < tcp_start + 20 and ihl != 5:
        continue
      src_port = struct.unpack("!H", raw_data[34:36])[0]
      server_seq = raw_data[38:42]

      if src_mac_raw == mac and src_port == port:
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
    print("[+] SYN packet sent successfully and waiting for ACK")
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
    except Exception as e:
      print(f"[-] Failed to send ACK packet: {e}")
      sys.exit(1)
  

if __name__ == "__main__":
    main()