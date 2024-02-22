import lib.wifi.probe_request as PRQ
import argparse
import time
from datetime import datetime as dt

# um zu testen ob wifi Karte Monitoring mode unterstützt 'iw list eingeben'

parser = argparse.ArgumentParser()
parser.add_argument('--iface', type=str, required=True)
args = parser.parse_args()

if __name__ == '__main__':
    scanner = PRQ.Scanner(args.iface, count=0)
    print(f"Start sleep... ({dt.now().strftime('%H:%M:%S')})")
    time.sleep(120)
    print(f"... Ended sleep")
    scanner.stop()

    for i in scanner.data:
        print(f"({i.timestamp.strftime('%d/%m/%Y | %H:%M:%S')})\t\t[{i.mac}]\t\t{i.ssid}")
