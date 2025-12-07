from sniffer import start_sniffer

def main():
    print("[+] NIDS started. Sniffing traffic from all interfaces...")
    start_sniffer()

if __name__ == "__main__":
    main()
