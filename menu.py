import socket, subprocess, threading, docker
from packet_sniffer.sniffer import run_packet_sniffer
from mini_tcp_stack.tcp_stack import main


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

server = docker.from_env()

def start_surver_listener():
  try:
    container = server.containers.get("server_node")
    exec_log = container.exec_run("python3 /app/server.py", detach=True)
    print(exec_log)
  except Exception as e:
    print(f"[-] Error executing command: {e}")
  
    

client = docker.from_env()
def send_syn_packet():
  try:
    container = client.containers.get("client_node")
    exec_log = container.exec_run("python3 /app/mini_tcp_stack/tcp_stack.py")
    print(exec_log)
  except Exception as e:
    print(f"[-] Error executing command: {e}")



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

  sniffer_thread = threading.Thread(target=run_packet_sniffer, daemon=True)
  sniffer_thread.start()
  print("[*] Packet sniffer started in the background.")

  while True:
    print("[1]: Perform 3-way handshake")
    print("[2]: Exit")
    choice = input("Enter your choice: ")
    if choice == '1':
      print('1が選ばれました。リスナーを起動します...')
      start_surver_listener()
      send_syn_packet()
    elif choice == '2':
      break

if __name__ == "__main__":
  main()
 
