import struct, socket, sys, subprocess
from telnetlib import IP
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

def create_packet(src_ip, dst_ip, src_port, dst_port, seq_num):
  # ==========================  
  # Create Ethernet layer
  # ==========================
  src_mac = get_my_mac(INTERFACE)
  dst_mac = get_dst_mac(dst_ip)
  eth_proto = b'\x08\x00'
  eth_header = dst_mac + src_mac + eth_proto

  # ==========================
  # Create IP layer
  # ==========================

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

  # ==========================
  # Create TCP layer with SYN flag set
  # ==========================
  ack_num = 0
  offset = 5
  reserved = 0
  flags = 0x02 #syn
  window = socket.htons(5840)
  checksum = 0
  urg_ptr = 0

  offset_flags = (offset << 12) | flags
  tcp_header_no_checksum = struct.pack(
    '!HHLLHHHH', src_port, dst_port, seq_num, ack_num, offset_flags, window, checksum, urg_ptr  
  )

  # ----------------------
  # Pseudo Header
  # ----------------------
  source_ip = socket.inet_aton(src_ip) 
  dest_ip = socket.inet_aton(dst_ip)
  placeholder = 0
  protocol = 6
  tcp_length = len(tcp_header_no_checksum)
  pseudo_header = struct.pack('!4s4sBBH', source_ip, dest_ip, placeholder, protocol, tcp_length)  
  psh = pseudo_header + tcp_header_no_checksum  
  tcp_check = get_checksum(psh)

  final_tcp_header = struct.pack(
    '!HHLLHHHH', src_port, dst_port, seq_num, ack_num, offset_flags, window, tcp_check, urg_ptr  
  )

  # ==========================
  # Combine layers and send it
  # ==========================
  packet = eth_header + ip_header + final_tcp_header
  return packet


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

  packet = create_packet(src_ip, dst_ip, src_port, dst_port, seq_num)

  s.sendto(packet, (INTERFACE, 0))
  print("[+] SYN packet sent successfully!")

if __name__ == "__main__":
    main()