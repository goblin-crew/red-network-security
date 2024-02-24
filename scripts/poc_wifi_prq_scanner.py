from scapy.packet import Packet
from scapy.layers import dot11 as d11
from scapy.sendrecv import AsyncSniffer
from datetime import datetime as dt
from dotenv import dotenv_values
import keyboard

config: dict = dotenv_values(dotenv_path=".env")

mac_assoc_table = {}

def handle_packet(pkt: Packet):
    if isinstance(pkt, Packet) and pkt.haslayer(d11.Dot11ProbeReq):
        timestamp = dt.now().strftime("%d/%m/%Y | %H:%M:%S")
        mac_addr: str = f"{pkt.addr2}"
        ssid: str = f"{pkt.info}"

        if mac_addr in mac_assoc_table:
            mac_assoc_table[mac_addr] += [ssid]

        else:
            mac_assoc_table[mac_addr] = [ssid]

        print(f"({timestamp})\t[{mac_addr}]\t-->\t{ssid}")

sniffer: AsyncSniffer = AsyncSniffer(iface=config["IFACE"], prn=handle_packet, count=0, store=False)

print("Start Sniffer...")
sniffer.start()

while True:
    if keyboard.read_key() == "q":
        print("received QUIT...")
        break

print("stop sniffer...")
sniffer.stop()
print("stopped sniffer...")