import socket

def main():
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  
  server_socket.bind(('0.0.0.0', 80))
  server_socket.listen(5)
  
  print("[*] サーバーが起動しました。継続して接続を待ち受けます...")

  try:
    while True:
      client_socket, addr = server_socket.accept()
      print(f"\n[+] 新しい接続を検知しました: {addr}")
      try:
        client_socket.settimeout(10.0)
        raw_data = client_socket.recv(4096)
        if raw_data:
          print("[*] 受け取ったデータ:")
          print(raw_data.decode('utf-8', errors='ignore'))
          response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
          client_socket.sendall(response)
        else:
          print("[-] クライアント側から接続が切断されました。")
      except socket.timeout:
          print("[-] ⚠️ 10秒間通信がなかったため、タイムアウトによりコネクションを強制終了します。")
      finally:
        client_socket.close()
        print("[-] この接続とのやり取りを終了しました。次の接続を待ちます...")

  except KeyboardInterrupt:
      print("\n[*] サーバーを手動で停止します。")
  finally:
      server_socket.close()

if __name__ == '__main__':
  main()