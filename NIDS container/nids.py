# nids.py
from sniffer import start_sniffer

def main():
    print("[+] Simple NIDS started.")
    start_sniffer(interface="eth0")

if __name__ == "__main__":
    main()
