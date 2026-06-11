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
    # Menggunakan raw string (r) agar tidak terkena SyntaxWarning dan merubah teks menjadi TUBES CS NETSCAN
    print(r"""
 /$$$$$$$$ /$$   /$$ /$$$$$$$  /$$$$$$$$  /$$$$$$         /$$$$$$   /$$$$$$        /$$   /$$ /$$$$$$$$ /$$$$$$$$ /$$$$$$   /$$$$$$   /$$$$$$  /$$   /$$
|__  $$__/| $$  | $$| $$__  $$| $$_____/ /$$__  $$       /$$__  $$ /$$__  $$      | $$$ | $$| $$_____/|__  $$__//$$__  $$ /$$__  $$ /$$__  $$| $$$ | $$
   | $$   | $$  | $$| $$  \ $$| $$      | $$  \__/      | $$  \__/| $$  \__/      | $$$$| $$| $$         | $$  | $$  \__/| $$  \__/| $$  \ $$| $$$$| $$
   | $$   | $$  | $$| $$$$$$$ | $$$$$   |  $$$$$$       | $$      |  $$$$$$       | $$ $$ $$| $$$$$      | $$  |  $$$$$$ | $$      | $$$$$$$$| $$ $$ $$
   | $$   | $$  | $$| $$__  $$| $$__/    \____  $$      | $$       \____  $$      | $$  $$$$| $$__/      | $$   \____  $$| $$      | $$__  $$| $$  $$$$
   | $$   | $$  | $$| $$  \ $$| $$       /$$  \ $$      | $$    $$ /$$  \ $$      | $$\  $$$| $$         | $$   /$$  \ $$| $$    $$| $$  | $$| $$\  $$$
   | $$   |  $$$$$$/| $$$$$$$/| $$$$$$$$|  $$$$$$/      |  $$$$$$/|  $$$$$$/      | $$ \  $$| $$$$$$$$   | $$  |  $$$$$$/|  $$$$$$/| $$  | $$| $$ \  $$
   |__/    \______/ |_______/ |________/ \______/        \______/  \______/       |__/  \__/|________/   |__/   \______/  \______/ |__/  |__/|__/  \__/                                                                                                                                                                                                                                                                                                                                                                                                                                                             
                                                                                            
                     -- Pemindai Jaringan Lokal Berbasis Python --
    """)

def get_local_ip():
    os_type = platform.system().lower()
    ip_address = None
    netmask = None

    try:
        if "windows" in os_type:
            result = subprocess.run(["ipconfig"], capture_output=True, text=True)
            # Memisahkan output ipconfig berdasarkan blok adapter jaringan
            adapters = result.stdout.split("\n\n")
            
            for adapter in adapters:
                # Lewati adapter jika itu adalah bagian dari VirtualBox atau VMware
                if "virtualbox" in adapter.lower() or "vmware" in adapter.lower():
                    continue
                
                # Cari IP dan Mask pada adapter fisik yang tersisa (seperti Wi-Fi atau Ethernet)
                ip_match = re.search(r"IPv4 Address[\.\s]*:\s*([0-9\.]+)", adapter)
                mask_match = re.search(r"Subnet Mask[\.\s]*:\s*([0-9\.]+)", adapter)
                
                if ip_match and mask_match:
                    # Pastikan IP tersebut bukan IP loopback atau kosong
                    if not ip_match.group(1).startswith("0."):
                        ip_address = ip_match.group(1)
                        netmask = mask_match.group(1)
                        break # Keluar dari loop jika sudah menemukan IP fisik aktif

        else:  # Linux atau macOS
            result = subprocess.run(["ifconfig"], capture_output=True, text=True)
            # Penyaringan teroptimasi untuk Linux, mengabaikan interface loopback (lo) dan virtual docker/vbox
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

    # Mekanisme Cadangan (Fallback) jika deteksi adapter di atas masih meleset
    if not ip_address:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Menghubungkan ke IP publik memancing OS memberikan IP lokal utama yang terhubung ke internet
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            netmask = "255.255.255.0"
            s.close()
        except Exception:
            print("[-] Gagal mendeteksi jaringan lokal otomatis.")
            sys.exit(1)

    return ip_address, netmask

def mask_to_cidr(mask):
    # Mengubah dot-decimal mask menjadi format angka CIDR (contoh: 24)
    try:
        return sum(bin(int(x)).count('1') for x in mask.split('.'))
    except Exception:
        return 24  # Default ke /24 jika terjadi error

def parse_network(arg=None):
    if arg is None:
        # Jika user tidak memasukkan input IP manual, deteksi otomatis jaringan saat ini
        ip, mask = get_local_ip()
        cidr = mask_to_cidr(mask)
        # Membuat network address (misal: 192.168.1.0/24)
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
    
    # Sesuaikan perintah ping berdasarkan Sistem Operasi
    if "windows" in os_type:
        # -n 1: kirim 1 paket, -w 500: timeout 500 milidetik
        cmd = ["ping", "-n", "1", "-w", "500", ip_str]
    else:
        # -c 1: kirim 1 paket, -W 1: timeout 1 detik
        cmd = ["ping", "-c", "1", "-W", "1", ip_str]
        
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Jika returncode adalah 0, berarti host memberikan respons (Online)
    if result.returncode == 0:
        return ip_str
    return None

def scan_network(network):
    print(f"[*] Memulai pemindaian pada jaringan: {network}")
    print("[*] Mohon tunggu beberapa detik...\n")
    
    online_machines = []
    # Mengambil seluruh daftar host valid dalam subnet (melewati network & broadcast ID)
    hosts = list(network.hosts())
    
    # Menjalankan pemindaian paralel menggunakan maksimum 50 utas (threads)
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(ping_host, hosts)
        
        for res in results:
            if res:
                online_machines.append(res)
                
    return online_machines

def port_scan_host(ip, ports=None, timeout=0.5):
    if ports is None:
        ports = [21,22,23,25,53,80,110,139,143,443,445,3389,8080]
    open_ports = []
    def _scan(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    return port
        except Exception:
            return None
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(_scan, ports)
        for r in results:
            if r:
                open_ports.append(r)

    return sorted(open_ports)

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
            if openp:
                results[h] = openp
    return results

def lan_scan():
    """Ambil entri ARP lokal dengan menjalankan `arp -a` dan parsing outputnya."""
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        out = result.stdout
    except Exception:
        return {}

    entries = {}
    # Baris bisa berbeda per OS; cari pola IP dan MAC
    for line in out.splitlines():
        line = line.strip()
        # ambil IP
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac_match = re.search(r"([0-9A-Fa-f]{2}[:-](?:[0-9A-Fa-f]{2}[:-]){4}[0-9A-Fa-f]{2})", line)
        if ip_match and mac_match:
            ip = ip_match.group(1)
            mac = mac_match.group(1)
            entries[ip] = mac
    return entries

def intrusion_detection(network, interval=10):
    """Sederhana: pantau perubahan ARP lokal dan laporkan anomali."""
    print("[*] Memulai Intrusion Detection (tekan Ctrl+C untuk berhenti)")
    prev = {}
    try:
        while True:
            arp = lan_scan()
            # Deteksi host baru / hilang
            new_hosts = set(arp.keys()) - set(prev.keys())
            gone_hosts = set(prev.keys()) - set(arp.keys())
            for ip in new_hosts:
                print(f"[ALERT] Host baru terdeteksi: {ip} -> {arp[ip]}")
            for ip in gone_hosts:
                print(f"[INFO] Host hilang: {ip} (sebelumnya {prev.get(ip)})")

            # Deteksi perubahan MAC untuk IP yang sama
            for ip, mac in arp.items():
                if ip in prev and prev[ip] != mac:
                    print(f"[WARNING] MAC berubah untuk {ip}: {prev[ip]} -> {mac}")

            # Deteksi MAC duplikat (kemungkinan spoofing)
            mac_to_ips = {}
            for ip, mac in arp.items():
                mac_to_ips.setdefault(mac, []).append(ip)
            for mac, ips in mac_to_ips.items():
                if len(ips) > 1:
                    print(f"[CRITICAL] MAC {mac} muncul di beberapa IP: {', '.join(ips)}")

            prev = arp
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
    --ids         Jalankan simple IDS yang memantau perubahan ARP

Contoh Perintah:
  python net_scan.py                 <- Deteksi otomatis & pindai jaringan saat ini
  python net_scan.py 192.168.1.0/24  <- Memindai blok subnet tertentu secara manual
    """)

def main():
    print_app_name()
    args = sys.argv[1:]
    
    # Cek jika ada argumen bantuan
    if len(args) > 0 and (args[0] == "-h" or args[0] == "--help"):
        show_help()
        sys.exit(0)
        
    # Tentukan segmen jaringan yang akan dipindai
    # CLI: Port scan
    if len(args) >= 1 and (args[0] == "-p" or args[0] == "--portscan"):
        if len(args) < 2:
            print("[-] Gunakan: --portscan <IP|network>")
            sys.exit(1)
        target = args[1]
        try:
            net = ipaddress.ip_network(target, strict=False)
            hosts = [str(h) for h in net.hosts()]
        except Exception:
            hosts = [target]

        if len(hosts) == 1:
            open_ports = port_scan_host(hosts[0])
            print(f"[RESULT] {hosts[0]} open ports: {open_ports}")
        else:
            res = port_scan_network(hosts)
            for h, ports in res.items():
                print(f"[RESULT] {h} open ports: {ports}")
        sys.exit(0)

    # CLI: LAN scan
    if len(args) >= 1 and args[0] == "--lanscan":
        entries = lan_scan()
        print("=" * 45)
        print(f" LAN ARP ENTRIES: {len(entries)}")
        print("=" * 45)
        for ip, mac in entries.items():
            print(f" {ip} -> {mac}")
        print("=" * 45)
        sys.exit(0)

    # CLI: IDS
    if len(args) >= 1 and args[0] == "--ids":
        if len(args) == 2:
            target_network = parse_network(args[1])
        else:
            target_network = parse_network()
        intrusion_detection(target_network)
        sys.exit(0)

    # Default: scan network
    if len(args) == 1:
        target_network = parse_network(args[0])
    else:
        target_network = parse_network()
        
    # Eksekusi scanning dan tampung hasilnya
    active_hosts = scan_network(target_network)
    
    # Tampilkan output hasil pemindaian ke layar dalam bentuk baris terstruktur
    print("=" * 45)
    print(f" HASIL PEMINDAIAN: {len(active_hosts)} PERANGKAT AKTIF")
    print("=" * 45)
    for host in active_hosts:
        print(f" [ONLINE] Perangkat ditemukan pada IP: {host}")
    print("=" * 45)

if __name__ == "__main__":
    main()