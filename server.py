import socket
import struct

def main():
  recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

  send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

  print("[*] Server is now listening")

  while True:
    packet, addr = recv_socket.recvfrom(65535)
    print(f"[*] Received packet from {addr}")

    ip_header = packet[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])

    if protocol == 6:  # TCP
      tcp_header = packet[20:40]
      tcph = struct.unpack('!HHLLBBHHH', tcp_header)
      src_port = tcph[0]
      dst_port = tcph[1]
      flags = tcph[5]

      syn_flag = (flags & 0x02) >> 1
      if syn_flag and dst_port == 80:
        print(f"[*] SYN packet received from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
        # TODO: Implement SYN-ACK response logic here
        pass

if __name__ == "__main__":
  main() 