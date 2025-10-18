#!/usr/bin/env python3
import socket
import sys

# Timeout global para operaciones de socket
socket.setdefaulttimeout(21)

HOST = "192.168.100.53"   # <<< Cambia a la IP del servidor FTP real (no .255)
PORT = 21

# Patrones a buscar en el banner (en minúsculas para comparación case-insensitive)
BANNERS = {
    "freefloat ftp server (version 1.00)": "[+] FreeFloat FTP Server is vulnerable.",
    "3com 3cdaemon ftp server version 2.0": "[+] 3CDaemon FTP Server is vulnerable.",
    "ability server 2.34": "[+] Ability FTP Server is vulnerable.",
    "sami ftp server 2.0.2": "[+] Sami FTP Server is vulnerable.",
}

def check_ftp_banner(host, port):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # opcional: s.settimeout(3)  # ya pusimos setdefaulttimeout
        # connect puede lanzar OSError / socket.timeout
        s.connect((host, port))
        # Muchos servidores FTP envían banner al conectarse; leerlo
        raw = s.recv(2048)
        if not raw:
            print("[-] No banner received (server did not send data).")
            return
        # Decodificar bytes a str (ignorar errores si hay bytes raros)
        banner = raw.decode(errors="ignore").strip()
        banner_l = banner.lower()
        print(f"[i] Banner: {banner}")

        for key, msg in BANNERS.items():
            if key in banner_l:
                print(msg)
                return

        print("[-] FTP Server is not recognized/vulnerable by this script.")
    except socket.timeout:
        print("[-] Connection timed out.")
    except OSError as e:
        # Aquí aparecerá Errno 101 si la red no tiene ruta
        print(f"[-] OSError while connecting/receiving: {e!s}")
    finally:
        if s:
            try:
                s.close()
            except Exception:
                pass

if __name__ == "__main__":
    # Permitir pasar la IP como argumento opcional
    if len(sys.argv) > 1:
        HOST = sys.argv[1]
    check_ftp_banner(HOST, PORT)
