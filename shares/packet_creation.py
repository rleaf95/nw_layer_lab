import socket,  struct, time

def get_checksum(psh):
  s = 0
  for i in range(0, len(psh), 2):
    w = (psh[i] << 8) + (psh[i+1] if i + 1 < len(psh) else 0)
    s += w
  while s >> 16:
    s = (s & 0xffff) + (s >> 16)  
  return ~s & 0xffff

def send_broadcast(dest_ip, dest_port=80):
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  try:
    sock.sendto(b'Hello', (dest_ip, dest_port))
  except Exception as e:
    print(f"[-] Failed to trigger ARP: {e}")
  finally:
    sock.close()

def get_dst_mac(target_ip):
  for attempt in range(3):
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
    except Exception as e:
      print(f"Failed to read ARP table: {e}. \nSending Broadcast .....")
    if attempt == 0:
      send_broadcast(target_ip)
      time.sleep(0.1)
    else:
      time.sleep(0.1)
  print(f"[-] Error: Could not resolve MAC address for {target_ip}")
  return None

def get_my_mac(interface="eth0"):
  try:
    with open(f"/sys/class/net/{interface}/address", "r") as f:
      mac_str = f.read().strip()
      return bytes.fromhex(mac_str.replace(":", ""))
  except Exception as e:
    print(f"Failed to get my MAC/ file name: {interface}:{e}")

def creat_eth_header(dst_ip, interface):
  src_mac = get_my_mac(interface)
  dst_mac = get_dst_mac(dst_ip)
  eth_proto = b'\x08\x00'
  # print(f'dst_mac{dst_mac} + src_mac{src_mac}')
  return dst_mac + src_mac + eth_proto

def create_ip_header(src_ip, dst_ip, payload=None):
  version = 4
  ihl = 5
  tos = 0
  if payload:
    tot_len = 20 + 20 + len(payload)
  else:
    tot_len = 20 + 20
  id = 54321
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
  actual_checksum = get_checksum(ip_header)
  ip_header = struct.pack(
    '!BBHHHBBH4s4s', version_ihl, tos, tot_len, id, frag, ttl, protocol, actual_checksum, src_ip_bytes, dst_ip_bytes
  )
  return ip_header

def create_tcp_header(src_port, dst_port, seq_num, ack_num, tcp_check=False, ack=False, payload=False):
  offset = 5
  reserved = 0
  if payload:
    flags = 0x18
  else:
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

def create_tcp_check(src_ip, dst_ip, tcp_header_no_cks, payload=False):

  source_ip = socket.inet_aton(src_ip) 
  dest_ip = socket.inet_aton(dst_ip)
  placeholder = 0
  protocol = 6
  payload_len = len(payload) if payload else 0
  tcp_length = len(tcp_header_no_cks) + payload_len
  pseudo_header = struct.pack('!4s4sBBH', source_ip, dest_ip, placeholder, protocol, tcp_length)  
  psh = pseudo_header + tcp_header_no_cks + (payload if payload else b"")
  tcp_check = get_checksum(psh)
  return tcp_check

