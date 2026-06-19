import sys  # Untuk argumen command-line dan keluar dari program
import socket  # Untuk operasi soket jaringan dan IP
import ipaddress  # Untuk kalkulasi rentang subnet IP
import concurrent.futures  # Untuk eksekusi multi-threading (paralel)
import platform  # Untuk mendeteksi sistem operasi (Windows/Linux)
import subprocess  # Untuk menjalankan perintah OS (ping, ipconfig, ifconfig)
import re  # Untuk regular expression (menyaring teks output IP)
import os  # Untuk operasi sistem dasar tambahan
import time  # Untuk delay di IDS

def print_app_name():
    print(r"""
█   █ █████ █████  ████  ███   ███  █   █ 
██  █ █       █   █     █     █   █ ██  █ 
█ █ █ ████    █    ███  █     █████ █ █ █ 
█  ██ █       █       █ █     █   █ █  ██ 
█   █ █████   █   ████   ███  █   █ █   █

-- Pemindai Jaringan Lokal Berbasis Python --
    """)

def get_local_ip():
    os_type = platform.system().lower()
    ip_address = None
    netmask = None

    try:
        if "windows" in os_type:
            result = subprocess.run(["ipconfig"], capture_output=True, text=True)
            adapters = result.stdout.split("\n\n")
            
            for adapter in adapters:
                if "virtualbox" in adapter.lower() or "vmware" in adapter.lower():
                    continue
                
                ip_match = re.search(r"IPv4 Address[\.\s]*:\s*([0-9\.]+)", adapter)
                mask_match = re.search(r"Subnet Mask[\.\s]*:\s*([0-9\.]+)", adapter)
                
                if ip_match and mask_match:
                    if not ip_match.group(1).startswith("0."):
                        ip_address = ip_match.group(1)
                        netmask = mask_match.group(1)
                        break

        else:  # Linux atau macOS
            result = subprocess.run(["ifconfig"], capture_output=True, text=True)
            blocks = result.stdout.split("\n\n")
            for block in blocks:
                if block.startswith("lo") or "vboxnet" in block or "docker" in block:
                    continue
                ip_match = re.search(r"inet\s+([0-9\.]+)", block)
                mask_match = re.search(r"netmask\s+([0-9\.]+)", block)
                if ip_match and mask_match:
                    ip_address = ip_match.group(1)
                    netmask = mask_match.group(1)
                    break
            
    except Exception:
        pass

    if not ip_address:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            netmask = "255.255.255.0"
            s.close()
        except Exception:
            print("[-] Gagal mendeteksi jaringan lokal otomatis.")
            sys.exit(1)

    return ip_address, netmask

def mask_to_cidr(mask):
    try:
        return sum(bin(int(x)).count('1') for x in mask.split('.'))
    except Exception:
        return 24

def parse_network(arg=None):
    if arg is None:
        ip, mask = get_local_ip()
        cidr = mask_to_cidr(mask)
        network_str = f"{ip}/{cidr}"
        return ipaddress.ip_network(network_str, strict=False)
    else:
        try:
            return ipaddress.ip_network(arg, strict=False)
        except ValueError:
            print(f"[-] Input jaringan tidak valid: {arg}")
            sys.exit(1)

def ping_host(ip):
    os_type = platform.system().lower()
    ip_str = str(ip)
    
    if "windows" in os_type:
        cmd = ["ping", "-n", "1", "-w", "500", ip_str]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip_str]
        
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        return ip_str
    return None

def scan_network(network):
    print(f"[*] Memulai pemindaian pada jaringan: {network}")
    print("[*] Mohon tunggu beberapa detik...\n")
    
    online_machines = []
    hosts = list(network.hosts())
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(ping_host, hosts)
        for res in results:
            if res:
                online_machines.append(res)
                
    return online_machines

def port_scan_host(ip, ports=None, timeout=0.5):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]
    open_ports = []

    def _scan(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    s.settimeout(1.0)
                    banner = ""
                    bytes_count = 0
                    try:
                        if port in [80, 8080, 443]:
                            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        
                        banner_bytes = s.recv(512)
                        bytes_count = len(banner_bytes)
                        banner = banner_bytes.decode(errors="ignore").strip()
                    except Exception:
                        pass
                    
                    return {
                        "port": port,
                        "banner": banner,
                        "bytes": bytes_count
                    }
        except Exception:
            return None
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(_scan, ports)
        for r in results:
            if r:
                open_ports.append(r)

    return sorted(open_ports, key=lambda x: x["port"])

def port_scan_network(hosts, ports=None):
    print(f"[*] Menjalankan port scan pada {len(hosts)} host...")
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_host = {executor.submit(port_scan_host, h, ports): h for h in hosts}
        for fut in concurrent.futures.as_completed(future_to_host):
            h = future_to_host[fut]
            try:
                openp = fut.result()
            except Exception:
                openp = []
            results[h] = openp
    return results

PORT_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    3389: "rdp",
    8080: "http-alt",
}

def verify_metasploitable(port, banner):
    if not banner:
        return ""
    b_lower = banner.lower()
    
    if "vsftpd 2.3.4" in b_lower:
        return " -> Terverifikasi: vsFTPd 2.3.4 (Metasploitable Backdoor Vulnerable!)"
    elif "openssh 4.7p1" in b_lower:
        return " -> Terverifikasi: OpenSSH 4.7p1 (Metasploitable Linux Target)"
    elif "apache/2.2.8" in b_lower:
        return " -> Terverifikasi: Apache HTTPD 2.2.8 (Metasploitable Web)"
    elif "samba" in b_lower or "3.0.20" in b_lower:
        return " -> Terverifikasi: Samba 3.x (Metasploitable Device)"
    elif "unrealircd" in b_lower or "unreal32" in b_lower:
        return " -> Terverifikasi: UnrealIRCd (Metasploitable IRC Backdoor)"
    
    clean_b = banner.replace('\r', '').replace('\n', ' ')
    return f" -> Banner asli: {clean_b[:35]}"

def lan_scan():
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        out = result.stdout
    except Exception:
        return {}

    entries = {}
    for line in out.splitlines():
        line = line.strip()
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac_match = re.search(r"([0-9A-Fa-f]{2}[:-](?:[0-9A-Fa-f]{2}[:-]){4}[0-9A-Fa-f]{2})", line)
        if ip_match and mac_match:
            ip = ip_match.group(1)
            mac = mac_match.group(1).lower().replace(':', '-')
            entries[ip] = mac
    return entries

def intrusion_detection(network, interval=10):
    print("[*] Memulai Intrusion Detection (tekan Ctrl+C untuk berhenti)")
    print("[*] Mengawasi ARP Spoofing & Anomali Banner Size (> 32 Bytes)...\n")
    prev = {}
    try:
        while True:
            arp = lan_scan()
            new_hosts = set(arp.keys()) - set(prev.keys())
            gone_hosts = set(prev.keys()) - set(arp.keys())
            
            # Filter alamat IP broadcast / multicast agar tidak masuk deteksi
            for ip in list(new_hosts):
                if ip.endswith('.255') or ip.startswith('224.') or ip.startswith('239.') or ip == '255.255.255.255':
                    new_hosts.remove(ip)

            for ip in new_hosts:
                print(f"[ALERT] Host baru terdeteksi di LAN: {ip} -> {arp[ip]}")
            for ip in gone_hosts:
                if not (ip.endswith('.255') or ip.startswith('224.') or ip == '255.255.255.255'):
                    print(f"[INFO] Host terputus: {ip}")

            mac_to_ips = {}
            for ip, mac in arp.items():
                # Filter agar IP broadcast tidak mengotori pemetaan MAC
                if ip.endswith('.255') or ip.startswith('224.') or ip == '255.255.255.255':
                    continue
                mac_to_ips.setdefault(mac, []).append(ip)

            # --- PERBAIKAN: Saring MAC Broadcast & Multicast Bawaan OS ---
            for mac, ips in mac_to_ips.items():
                if mac in ["ff-ff-ff-ff-ff-ff", "01-00-5e-00-00-02", "01-00-5e-00-00-16", "01-00-5e-00-00-fb", "01-00-5e-00-00-fc", "01-00-5e-7f-ff-fa"]:
                    continue
                if len(ips) > 1:
                    print(f"[CRITICAL] Serangan MITM Aktif! MAC {mac} dipakai massal oleh: {', '.join(ips)}")

            print("[IDS-CHECK] Memindai panjang data respon banner dari perangkat fisik aktif...")
            active_hosts = [ip for ip in arp.keys() if not (ip.endswith('.255') or ip.startswith('224.') or ip == '255.255.255.255')]
            
            for host in active_hosts:
                try:
                    open_entries = port_scan_host(host)
                    for entry in open_entries:
                        if entry["bytes"] > 32:
                            # Tampilkan info detail bahwa ini kemungkinan service web biasa jika portnya 80/8080
                            notes = " (HTTP Header/Banner Biasa)" if entry["port"] in [80, 8080, 443] else ""
                            print(f"  [IDS ALERT] Potensi Eksploitasi/Anomali payload pada {host}:{entry['port']} -> Terbaca {entry['bytes']} Bytes (>32!){notes}")
                except Exception:
                    pass

            prev = arp
            print(f"[IDS] Tidur selama {interval} detik sebelum siklus pengawasan berikutnya...\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Intrusion Detection dihentikan oleh pengguna.")

def show_help():
    print("""
Penggunaan: python net_scan.py [OPSI/JARINGAN]

Opsi:
  -h, --help    Menampilkan menu bantuan ini
    -p, --portscan <IP|NETWORK>   Pindai port pada IP tunggal atau seluruh subnet
    --lanscan     Tampilkan tabel ARP lokal (IP -> MAC)
    --ids         Jalankan simple IDS yang memantau perubahan ARP & Byte Anomali

Contoh Perintah:
  python net_scan.py                 <- Deteksi otomatis & pindai jaringan saat ini
  python net_scan.py 192.168.1.0/24  <- Memindai blok subnet tertentu secara manual
    """)

def main():
    print_app_name()
    args = sys.argv[1:]
    
    if len(args) > 0 and (args[0] == "-h" or args[0] == "--help"):
        show_help()
        sys.exit(0)
        
    if len(args) >= 1 and args[0] == "--lanscan":
        entries = lan_scan()
        print("=" * 60)
        print(f" TABEL LAN ARP ENTRIES (TOTAL PERANGKAT: {len(entries)})")
        print("=" * 60)
        for ip, mac in entries.items():
            print(f" [DEVICE] IP Target: {ip.ljust(15)} ---> MAC Address: {mac}")
        print("=" * 60)
        sys.exit(0)

    if len(args) >= 1 and args[0] == "--ids":
        if len(args) == 2:
            target_network = parse_network(args[1])
        else:
            target_network = parse_network()
        intrusion_detection(target_network)
        sys.exit(0)

    if len(args) == 1:
        target_network = parse_network(args[0])
    else:
        target_network = parse_network()
        
    active_hosts = scan_network(target_network)
    port_results = port_scan_network(active_hosts)

    print("\n" + "=" * 65)
    print(f"Scan pada jaringan: {target_network}")
    print(f"Perangkat aktif: {len(active_hosts)}\n")

    output_file = "Port scan seluruh subnet.txt"
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"Scan pada jaringan: {target_network}\n")
            f.write(f"Perangkat aktif: {len(active_hosts)}\n\n")
            
            for i, h in enumerate(active_hosts):
                ports = port_results.get(h, [])
                
                print(f"[ONLINE] {h}")
                f.write(f"[ONLINE] {h}\n")

                if ports:
                    for entry in ports:
                        port = entry["port"]
                        banner = entry["banner"]
                        bytes_len = entry["bytes"]
                        
                        expected_service = PORT_SERVICES.get(port, "unknown")
                        meta_info = verify_metasploitable(port, banner)
                        warning_flag = " [WARNING: bytes > 32]" if bytes_len > 32 else ""
                        
                        pstr = f"{port}/tcp ({expected_service}){meta_info}{warning_flag}"
                        print(f"    {pstr}")
                        f.write(f"    {pstr}\n")
                else:
                    print("    []")
                    f.write("    []\n")
                
                if i < len(active_hosts) - 1:
                    print()
                    f.write("\n")
                    
        print("=" * 65)
        print(f"[*] Hasil lengkap sukses dicatat ke: {output_file}")
    except Exception as e:
        print(f"[-] Gagal menulis hasil ke {output_file}: {e}")

if __name__ == "__main__":
    main()