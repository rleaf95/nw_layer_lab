
# Network Security & Packet Engineering Lab

ゼロからネットワークプロトコルや脆弱性を自作コードとDockerラボで検証するプロジェクト。

## 🏗️ アーキテクチャ図
[sniffer_node] <---> [仮想ブリッジ (lab-net)] <---> [attacker_node / target_node]

## Plan
- **01_packet_sniffer**: 生ソケットによるL2/L3パケットスニッファの自作
- **02_custom_ping**: ICMPプロトコルの自作
- **03_arp_spoofing**: ARPスプーフィングと通信傍受の検証

docker compose up -> running menu.py >