import socket, subprocess, threading, docker, time, logging
from packet_sniffer.sniffer import run_packet_sniffer
from spoofer.arp_spoof import run_spoofer
from client.tcp_stack import main

logging.basicConfig(
  filename="/app/system_debug.log",
  level=logging.INFO,
  format="[%(asctime)s] [%(name)s] %(message)s",
  datefmt="%H:%M:%S"
)
logger = logging.getLogger('  SNIFFER ')
interface = 'eth0'



def get_my_mac(ifname):
  try:
    with open(f"/sys/class/net/{ifname}/address", "r") as f:
      return f.read().strip()
  except Exception:
    return "Unknown"


sniffer_ip = socket.gethostbyname('sniffer-node')
client_ip = socket.gethostbyname('client-node')
server_ip = socket.gethostbyname('server-node')

ip_dict = {
  sniffer_ip: {'name': 'sniffer', 'mac': get_my_mac(interface), 'socket': 'Unknown'},
  client_ip: {'name': 'client', 'mac': 'Unknown', 'socket': 'Unknown'},
  server_ip: {'name': 'server', 'mac': 'Unknown', 'socket': 'Unknown'}
}

def get_arp_table():
  try:
    with open("/proc/net/arp", "r") as f:
      lines = f.readlines()
      for line in lines[1:]:
        parts = line.split()
        ip = parts[0]
        mac = parts[3]
        if ip in ip_dict:
          ip_dict[ip]['mac'] = mac
  except Exception as e:
    print(f"ARP read error: {e}")

server = docker.from_env()
def start_surver_listener():
  try:
    container = server.containers.get("server_node")
    container.exec_run("python3 -u /app/server.py eth0", detach=True)
  except Exception as e:
      print(f"[-] Error executing command: {e}")
  

client = docker.from_env()
def start_client_listener():
  try:
    container = client.containers.get("client_node")
    container.exec_run(f"python3 -u /app/client/tcp_stack.py eth0 {interface}", detach=True)
  except Exception as e:
    print(f"[-] Error executing command: {e}")

def trigger_syn():
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sc:
    sc.connect(('client-node', 9999))
    sc.sendall(b"SEND_SYN")

def get_print_info():
  get_arp_table()
  print("==================================================")
  print("    [RUNNING] NETWORK LAYER LAB (CLI)   ")
  print("==================================================")
  for ip, info in ip_dict.items():
    print(f" [{info['name']:<8}] IP: {ip:<12} | MAC: {info['mac']}")
  print("==================================================")
  


def main():
  interface = input('Please enter the network interface (default: eth0):')
  for ip, info in ip_dict.items():
    if info['name'] != 'sniffer':
      subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
      
  get_print_info()
  sniffer_thread = threading.Thread(target=run_packet_sniffer, args=(interface, get_my_mac(interface), ip_dict, logger), daemon=True)
  sniffer_thread.start()
  logger.info("[*] Sniffer started in the background.")
  start_surver_listener()
  start_client_listener()

  time.sleep(1)
  while True:
    print("\n[1]: Perform 3-way handshake")
    print("[2]: Start ARP poisoner")
    print("[3]: Exit")
    choice = input("Enter your choice: ")
    print('')
    if choice == '1':
      trigger_syn()
      time.sleep(0.1)
    elif choice == '2':
      spoofer_thread = threading.Thread(target=run_spoofer, args=(interface, ip_dict, logger), daemon=True)
      spoofer_thread.start()
      time.sleep(0.1)
    elif choice == '3':
      break
    

if __name__ == "__main__":
  main()
 
