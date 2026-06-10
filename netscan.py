import sys  # Untuk argumen command-line dan keluar dari program
import socket  # Untuk operasi soket jaringan dan IP
import ipaddress  # Untuk kalkulasi rentang subnet IP
import concurrent.futures  # Untuk eksekusi multi-threading (paralel)
import platform  # Untuk mendeteksi sistem operasi (Windows/Linux)
import subprocess  # Untuk menjalankan perintah OS (ping, ipconfig, ifconfig)
import re  # Untuk regular expression (menyaring teks output IP)
import os  # Untuk operasi sistem dasar tambahan

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

def show_help():
    print("""
Penggunaan: python net_scan.py [OPSI/JARINGAN]

Opsi:
  -h, --help    Menampilkan menu bantuan ini

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