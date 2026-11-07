import socket
import subprocess
from packet_sniffer.sniffer import run_packet_sniffer

def get_my_mac(ifname="eth0"):
  try:
    with open(f"/sys/class/net/{ifname}/address", "r") as f:
      return f.read().strip()
  except Exception:
    return "Unknown"

sniffer_ip = socket.gethostbyname('sniffer-node')
client_ip = socket.gethostbyname('client-node')
server_ip = socket.gethostbyname('server-node')

ip_list = [
  {'name': 'sniffer', 'ip': sniffer_ip, 'mac': get_my_mac("eth0")},
  {'name': 'client', 'ip': client_ip, 'mac': 'Unknown'},
  {'name': 'server', 'ip': server_ip, 'mac': 'Unknown'}
]

def get_arp_table():
  try:
    with open("/proc/net/arp", "r") as f:
      lines = f.readlines()
      for line in lines[1:]:
        parts = line.split()
        ip = parts[0]
        mac = parts[3]
        for i in ip_list:
          if i['ip'] == ip:
            i['mac'] = mac
  except Exception as e:
    print(f"ARP read error: {e}")

def main():
  subprocess.run(["ping", "-c", "1", "-W", "1", ip_list[1]['ip']], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  subprocess.run(["ping", "-c", "1", "-W", "1", ip_list[2]['ip']], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  get_arp_table()
  print("==================================================")
  print("    [RUNNING] NETWORK LAYER LAB (CLI)   ")
  print("==================================================")
  for node in ip_list:
    print(f" [{node['name']:<8}] IP: {node['ip']:<12} | MAC: {node['mac']}")
  print("==================================================")

  run_packet_sniffer()


if __name__ == "__main__":
  main()

