import socket, logging

logging.basicConfig(
  filename="/app/system_debug.log",
  level=logging.INFO,
  format="[%(asctime)s] [%(name)s] %(message)s",
  datefmt="%H:%M:%S"
)
logger = logging.getLogger('SERVER')

def main():
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  
  server_socket.bind(('0.0.0.0', 80))
  server_socket.listen(5)
  
  logger.info("[*] Server listener started in the background ")


  try:
    while True:
      client_socket, addr = server_socket.accept()
      logger.info(f"[+] New connection from {addr}")
      try:
        raw_data = client_socket.recv(4096)
        if raw_data:
          request_text = raw_data.decode("utf-8", errors="ignore")
          logger.info(f"[+] data_get from {addr}\nrequest: {request_text}")
          if "/normal-page" in request_text:
            response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
          elif "/malicious-page" in request_text:
            response = (
              b"HTTP/1.1 302 Found\r\n"
              b"Location: http://malicious.com/\r\n"
              b"Content-Length: 0\r\n\r\n"
            )
          client_socket.sendall(response)
        else:
          logger.info(f"[-] Connection lost: {addr}")
          continue
      finally:
        client_socket.close()
        logger.info("[-] connection finnished: {addr}")

  except KeyboardInterrupt:
      print("\n[*] Server is stopped")
  finally:
      server_socket.close()

if __name__ == '__main__':
  main()