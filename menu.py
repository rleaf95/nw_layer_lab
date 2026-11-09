import socket, subprocess, threading, docker, time
from packet_sniffer.sniffer import run_packet_sniffer
from spoofer.arp_spoof import run_spoofer
from client.tcp_stack import main

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
ip_list = [
  {'name': 'sniffer', 'ip': sniffer_ip, 'mac': get_my_mac(interface)},
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
def stream_server_logs(container):
  try:
    exit_code, output_stream = container.exec_run("python3 -u /app/server.py", stream=True)
    for line in output_stream:
        decoded_line = line.decode('utf-8', errors='replace').strip()
        if decoded_line:
            print(f"[Server] {decoded_line}")
  except Exception as e:
      print(f"[-] Stream error: {e}")

def start_surver_listener():
  try:
    container = server.containers.get("server_node")
    log_thread = threading.Thread(target=stream_server_logs, args=(container,), daemon=True)
    log_thread.start()
  except Exception as e:
      print(f"[-] Error executing command: {e}")
  

client = docker.from_env()
def send_syn_packet():
  try:
    container = client.containers.get("client_node")
    exec_log = container.exec_run(f"python3 /app/client/tcp_stack.py {interface}")
    output_str = exec_log.output.decode('utf-8', errors='replace')
    if output_str.strip():
      for line in output_str.splitlines():
        print(f"[Client] {line}")
  except Exception as e:
    print(f"[-] Error executing command: {e}")

def get_print_info():
  get_arp_table()
  print("==================================================")
  print("    [RUNNING] NETWORK LAYER LAB (CLI)   ")
  print("==================================================")
  for node in ip_list:
    print(f" [{node['name']:<8}] IP: {node['ip']:<12} | MAC: {node['mac']}")
  print("==================================================")
  


def main():
  interface = input('Please enter the network interface (default: eth0):')
  subprocess.run(["ping", "-c", "1", "-W", "1", ip_list[1]['ip']], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  subprocess.run(["ping", "-c", "1", "-W", "1", ip_list[2]['ip']], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  get_print_info()
  sniffer_thread = threading.Thread(target=run_packet_sniffer, args=(interface, get_my_mac(interface),), daemon=True)
  sniffer_thread.start()
  start_surver_listener()
  print("[Sniffer] [*] Sniffer started in the background.")

  time.sleep(1)
  while True:
    print("\n[1]: Perform 3-way handshake")
    print("[2]: Start ARP poisoner")
    print("[3]: Exit")
    choice = input("Enter your choice: ")
    print('')
    if choice == '1':
      send_syn_packet()
      time.sleep(0.1)
    elif choice == '2':
      spoofer_thread = threading.Thread(target=run_spoofer, args=(interface, ip_list), daemon=True)
      spoofer_thread.start()
      time.sleep(0.1)
    elif choice == '3':
      break
    

if __name__ == "__main__":
  main()
 
