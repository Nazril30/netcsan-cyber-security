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
        cmd = ["ping", "-n", "1", "-w", "400", ip_str]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip_str]
        
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        return ip_str
    return None

def scan_network(network):
    print(f"[*] Melakukan Ping Sweep pada jaringan: {network}")
    print("[*] Mengidentifikasi host yang aktif, mohon tunggu...\n")
    
    online_machines = []
    hosts = list(network.hosts())
    if not hosts and network.num_addresses == 1:
        hosts = [network.network_address]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(ping_host, hosts)
        for res in results:
            if res:
                online_machines.append(res)
                
    return online_machines


def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            if s.connect_ex((ip, port)) != 0:
                return ""
            if port in [80, 8080]:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024)
            return banner.decode(errors="ignore").strip()
    except Exception:
        return ""


def check_tcp_port(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((str(ip), port)) == 0
    except OSError:
        return False


def check_udp_port(ip, port, timeout):
    if port != 53:
        return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            # Query DNS sederhana untuk memeriksa respons UDP port 53
            query = (
                b"\xaa\xaa"      # ID
                b"\x01\x00"      # flags: standard query
                b"\x00\x01"      # QDCOUNT
                b"\x00\x00"      # ANCOUNT
                b"\x00\x00"      # NSCOUNT
                b"\x00\x00"      # ARCOUNT
                b"\x03www\x06google\x03com\x00"
                b"\x00\x01"      # QTYPE A
                b"\x00\x01"      # QCLASS IN
            )
            s.sendto(query, (str(ip), port))
            s.recvfrom(512)
            return True
    except (socket.timeout, OSError):
        return False


def port_scan_host(ip, ports=None, timeout=1.0):
    if ports is None:
        # Daftar port standar esensial audit keamanan
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080]
    open_ports = []

    def _scan(port):
        try:
            if check_tcp_port(ip, port, timeout):
                return port
            if check_udp_port(ip, port, timeout):
                return port
        except Exception:
            return None
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(_scan, ports)
        for r in results:
            if r:
                open_ports.append(r)

    return sorted(open_ports)

def port_scan_network(hosts, ports=None):
    print(f"\n[*] Melakukan Port Scan simultan pada {len(hosts)} host aktif...")
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        future_to_host = {executor.submit(port_scan_host, h, ports): h for h in hosts}
        for fut in concurrent.futures.as_completed(future_to_host):
            h = future_to_host[fut]
            try:
                openp = fut.result()
            except Exception:
                openp = []
            results[h] = openp
    return results

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
            mac = mac_match.group(1).lower().replace("-", ":")
            entries[ip] = mac
    return entries

def intrusion_detection(interval=5):
    print("[*] Memulai Intrusion Detection (IDS) berbasis pemantauan ARP")
    print("[*] Mendeteksi anomali & ARP Spoofing... (Tekan Ctrl+C untuk berhenti)\n")
    prev = {}
    try:
        while True:
            arp = lan_scan()
            new_hosts = set(arp.keys()) - set(prev.keys())
            gone_hosts = set(prev.keys()) - set(arp.keys())
            
            for ip in new_hosts:
                if prev: # Jangan munculkan alert pada scanning iterasi pertama
                    print(f"[ALERT] Host baru masuk jaringan: {ip} -> [{arp[ip]}]")
            for ip in gone_hosts:
                print(f"[INFO] Host terputus/hilang: {ip} (sebelumnya {prev.get(ip)})")

            for ip, mac in arp.items():
                if ip in prev and prev[ip] != mac:
                    print(f"[CRITICAL WARNING] Dugaan ARP Spoofing! MAC berubah untuk IP {ip}: {prev[ip]} -> {mac}")

            # Deteksi MAC duplikat (kemungkinan spoofing)
            mac_to_ips = {}
            for ip, mac in arp.items():
                mac_to_ips.setdefault(mac, []).append(ip)
            for mac, ips in mac_to_ips.items():
                # REVISI: Abaikan alamat MAC broadcast universal agar tidak false alarm
                if mac == "ff:ff:ff:ff:ff:ff":
                    continue
                    
                if len(ips) > 1:
                    print(f"[CRITICAL] Indikasi MITM Attack! MAC [{mac}] duplikat di beberapa IP: {', '.join(ips)}")

            prev = arp
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Intrusion Detection System dihentikan oleh pengguna.")

def show_help():
    print("""
Penggunaan: python net_scan.py [OPSI/JARINGAN]

Opsi:
  -h, --help        Menampilkan menu bantuan ini
  --lanscan         Tampilkan tabel ARP lokal saat ini (IP -> MAC)
  --ids             Jalankan simple IDS untuk memantau mitigasi serangan ARP Spoofing

Contoh Perintah:
  python net_scan.py                 <- Otomatis lacak IP + cek port pada subnet aktif
  python net_scan.py 192.168.1.0/24  <- Pindai IP + cek port subnet manual
  python net_scan.py ip 192.168.18.1  <- Pindai host tunggal secara langsung
    """)

def main():
    print_app_name()
    args = sys.argv[1:]
    
    if len(args) > 0 and (args[0] == "-h" or args[0] == "--help"):
        show_help()
        sys.exit(0)
        
    if len(args) >= 1 and args[0] == "--lanscan":
        entries = lan_scan()
        print("=" * 55)
        print(f" TABEL LAN ARP ENTRIES (TOTAL PERANGKAT: {len(entries)})")
        print("=" * 55)
        for ip, mac in entries.items():
            print(f" [DEVICE] IP Target: {ip.ljust(15)} ---> MAC Address: {mac}")
        print("=" * 55)
        sys.exit(0)

    if len(args) >= 1 and args[0] == "--ids":
        intrusion_detection()
        sys.exit(0)

    # ALUR UTAMA (Penyatuan Otomatis: Subnet -> Ping Sweep -> Port Scan)
    if len(args) >= 2 and args[0].lower() == "ip":
        target_network = parse_network(args[1])
    elif len(args) == 1:
        target_network = parse_network(args[0])
    else:
        target_network = parse_network()
        
    # 1. Jalankan Network Scan (Ping Sweep)
    active_hosts = scan_network(target_network)
    
    # 2. Jalankan Port Scan langsung pada host yang berstatus Online
    port_results = {}
    if active_hosts:
        port_results = port_scan_network(active_hosts)
    
    # 3. Tampilkan Gabungan Output Akhir yang Komprehensif
    print("\n" + "=" * 65)
    print(f" HASIL KOMBINASI PEMINDAIAN: {len(active_hosts)} PERANGKAT AKTIF")
    print("=" * 65)
    
    if not active_hosts:
        print(" [!] Tidak ada host aktif yang ditemukan pada rentang subnet ini.")
    else:
        for host in active_hosts:
            open_ports = port_results.get(host, [])
            print(f"\n[ONLINE] {host}")

            if not open_ports:
                print("   Tidak ada port terbuka")
                continue

            for port in open_ports:
                try:
                    service = socket.getservbyport(port)
                except Exception:
                    service = "unknown"

                print(f"   {port}/tcp  ({service})")

    print("=" * 65)

if __name__ == "__main__":
    main()