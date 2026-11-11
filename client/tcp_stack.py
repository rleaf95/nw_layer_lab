import struct, socket, sys, os, datetime, threading, logging
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)
from shares.packet_creation import *
from shares.packet_dissection import *

logging.basicConfig(
  filename="/app/system_debug.log",
  level=logging.INFO,
  format="[%(asctime)s] [%(name)s] %(message)s",
  datefmt="%H:%M:%S"
)
logger = logging.getLogger('  CLIENT  ')

INTERFACE = sys.argv[1] if len(sys.argv) > 1 else "eth0"

def control_listener(s, src_ip, dst_ip, src_port, dst_port, seq_num, interface):
  try:
    ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctrl_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ctrl_sock.bind(('0.0.0.0', 9999))
    ctrl_sock.listen(1)
    logger.info("[+] Control listener bound to port 9999 and listening.")
  except Exception as e:
    logger.error(f"[-] Failed to bind or listen on port 9999: {e}")
    return
  
  while True:
    conn, _ = ctrl_sock.accept()
    try:
      data = conn.recv(1024).decode().strip()
      if data == "SEND_SYN":
        packet = create_packet(src_ip, dst_ip, src_port, dst_port, seq_num)
        s.sendto(packet, (interface, 0))
        logger.info(f"[+] Sent SYN packet to {dst_ip}")
    except Exception as e:
        logger.error(f"[-] Error in control listener: {e}")
    finally:
        conn.close()

def create_packet(src_ip, dst_ip, src_port, dst_port, seq_num):
  logger.info(f'[+] Start to create SYN packet - to {dst_ip}')
  eth_header = creat_eth_header(dst_ip, INTERFACE, logger)
  ip_header = create_ip_header(src_ip, dst_ip)
  ack_num = 0
  tcp_header_no_cks = create_tcp_header(src_port, dst_port, seq_num, ack_num)
  tcp_check = create_tcp_check(src_ip, dst_ip, tcp_header_no_cks)
  final_tcp_header = create_tcp_header(src_port, dst_port, seq_num, ack_num, tcp_check)

  return eth_header + ip_header + final_tcp_header
  

def create_ack_packet(src_ip, dst_ip, src_port, dst_port, seq_num, ack_num=None, payload=None):
  eth_header = creat_eth_header(dst_ip, INTERFACE)
  ip_header = create_ip_header(src_ip, dst_ip, payload=payload)

  tcp_header_no_cks = create_tcp_header(src_port, dst_port, seq_num, ack_num, tcp_check=False, ack=True, payload=payload)
  tcp_check = create_tcp_check(src_ip, dst_ip, tcp_header_no_cks, payload=payload)
  final_tcp_header = create_tcp_header(src_port, dst_port, seq_num, ack_num, tcp_check, True, payload)

  if payload:
    return eth_header + ip_header + final_tcp_header + payload
  return eth_header + ip_header + final_tcp_header


def listen(s, my_mac):
  try:
    raw_data, _ = s.recvfrom(65565)
    _, src_addr, _, eth_remain = ethernet_header(raw_data)

    if src_addr == my_mac:
      return None, None, None, None

    ip_header, ip_remain = ipv4_header(eth_remain)
    if ip_header['Protocol'] == 6:
      parsed_tcp_header, tcp_remian = parse_tcp_header(ip_remain)
      if parsed_tcp_header['Source Port'] == 80:
        payload_len = 0
        if parsed_tcp_header["PSH"] == 1:
          decode_payload = tcp_remian.decode('utf-8')
          logger.info(f'Received packet with payload\n[payload]\n{decode_payload}')
          payload_len = len(tcp_remian)
        flags = {
          "SYN": parsed_tcp_header["SYN"],
          "ACK": parsed_tcp_header["ACK"],
          "FIN": parsed_tcp_header["FIN"],
          "RST": parsed_tcp_header["RST"],
          "URG": parsed_tcp_header["URG"],
          "PSH": parsed_tcp_header["PSH"],
        }
        seq_num = parsed_tcp_header["Sequence Number"]
        ack_num = parsed_tcp_header["Acknowledgment Number"]
        return seq_num, ack_num, flags, payload_len, src_addr
  except socket.timeout:
    logger.error("[-] Timeout")
    return None, None, None, None
  except Exception as e:
    logger.error(f"[-] Error during listening/receiving: {e}")
    sys.exit(1)
    


def main():
  byte = get_my_mac(INTERFACE)
  my_mac = convert_to_mac(byte)
  src_ip = socket.gethostbyname('client-node')

  try:
    dst_ip = socket.gethostbyname("server-node")
  except socket.gaierror:
    logger.error('[-] Server not found')

  src_port = 54321
  dst_port = 80
  seq_num = 1000

  try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    logger.info("[*] Client listener started in the background ")
    
  except PermissionError:
    logger.error("[-] Error: permission error")
    sys.exit(1)

  ctrl_thread = threading.Thread(
    target=control_listener, 
    args=(s, src_ip, dst_ip, src_port, dst_port, seq_num, INTERFACE), 
    daemon=True
  )
  ctrl_thread.start()

  while True:
    result = listen(s, my_mac)

    if result is None or result[0] is None:
      continue
    
    # server's seq, server's ack
    ack_num, seq_num, flags, payload_len, src_addr = result

    if payload_len != 0:
      ack_num += payload_len
    elif flags.get("SYN") == 1:
      ack_num += 1
    elif flags.get("FIN") == 1:
      ack_num += 1

    if flags.get("SYN") == 1 and flags.get("ACK") == 1:
      logger.info(f"[+] Received SYN-ACK packet from {src_addr}")
      payload = b"GET /normal-page HTTP/1.1\r\n Host: server-node\r\n\r\n"
      ack_packet = create_ack_packet(src_ip, dst_ip, src_port, dst_port, seq_num, ack_num=ack_num, payload=payload)
      decode_payload = payload.decode('utf-8')
      logger.info(f"[+] Sent ACK-PSH packet with payload:\n[payload]\n{decode_payload}")
    elif (flags.get("ACK") == 1 and flags.get("FIN") == 1) or (flags.get("ACK") and flags.get("PSH")):
      ack_packet = create_ack_packet(src_ip, dst_ip, src_port, dst_port, seq_num, ack_num=ack_num)
      logger.info("[+] Sent ACK packet")
    else:
      continue

    try:
      s.sendto(ack_packet, (INTERFACE, 0))
    except Exception as e:
      logger.error(f"[-] Failed to send ACK packet: {e}")
      sys.exit(1)
      

if __name__ == "__main__":
  main()