import argparse
from colorama import *
import sys
from threading import Thread

from arp_spoof import arp_spoofing
from dhcp_starvation import dhcp_starvation
from rogue_dhcp import rogue_dhcp
from dhcp_release import dhcp_release_spoofing
from cam_overflow import cam_table_overflow
from dtp_spoof import dtp_spoofing
from eigrp_poison import eigrp_poisoning
from eigrp_k_abuse import eigrp_k_abusing
from eigrp_hello_flood import eigrp_hello_flooding
from eigrp_rto import eigrp_rto

def main():
    banner = f"""{Fore.RED}
        ███████╗ █████╗ ██╗     ███╗   ███╗ ██████╗ ███╗   ██╗███████╗██╗     ██╗ █████╗ 
        ██╔════╝██╔══██╗██║     ████╗ ████║██╔═══██╗████╗  ██║██╔════╝██║     ██║██╔══██╗
        ███████╗███████║██║     ██╔████╔██║██║   ██║██╔██╗ ██║█████╗  ██║     ██║███████║
        ╚════██║██╔══██║██║     ██║╚██╔╝██║██║   ██║██║╚██╗██║██╔══╝  ██║     ██║██╔══██║
        ███████║██║  ██║███████╗██║ ╚═╝ ██║╚██████╔╝██║ ╚████║███████╗███████╗██║██║  ██║
        ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝╚═╝  ╚═╝
        {Fore.CYAN}                          Network Penetration Testing Framework
        {Fore.RESET}"""

    attacks_table = f"""{Fore.CYAN}
    ┌────────────────┬──────────────────────────────────────────────────────────────────────┐
    │   Attack Type  │                          Description                                 │
    ├────────────────┼──────────────────────────────────────────────────────────────────────┤
    │ arp-spoof      │ ARP Spoofing ... (ARP Cache Poisoning)                               │
    │ dhcp-strv      │ DHCP Starvation ... (Pool Exhaustion)                                │
    │ rog-dhcp       │ Rogue DHCP Server ... (Malicious DHCP)                               │
    │ dhcp-rls       │ DHCP Release Spoofing ... (Force Release)                            │
    │ cam-overflow   │ CAM Table Overflow ... (MAC Address Table Overflow)                  │
    │ dtp-spoof      │ DTP Spoofing ... (Trunk Negotiation)                                 │
    │ eigrp-poison   │ EIGRP Poisoning ... (Route Injection)                                │
    │ eigrp-k        │ EIGRP K-values Abuse ... (Neighbor Disruption)                       │
    │ eigrp-hello    │ EIGRP Hello Flooding ... (Neighbor Table Overflow)                   │
    │ eigrp-rto      │ EIGRP Routing Table Overflow ... (Update Flooding)                   │
    └────────────────┴──────────────────────────────────────────────────────────────────────┘
    {Fore.RESET}"""

    # Список доступных атак
    available_attacks = ['arp-spoof', 'dhcp-strv', 'rog-dhcp', 'dhcp-rls', 'cam-overflow',
                         'dtp-spoof', 'eigrp-poison', 'eigrp-k', 'eigrp-hello', 'eigrp-rto']

    # Показать помощь если нет аргументов или запрошен help
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] in ['-h', '--help']):
        print(banner)
        print(attacks_table)
        print(f"{Fore.YELLOW}   [*] USAGE: sudo python3 salmonella.py <ATTACK_TYPE> [OPTIONS]")
        print(f"   [*] FOR SPECIFIC ATTACK OPTIONS: sudo python3 salmonella.py <ATTACK_TYPE> --help")
        print(f"\n   [*] WARNING: This tool is for authorized security testing only. Unauthorized use is illegal. Use responsibly.")
        print(f"   [*] VERSION: 1.0.0")
        print(f"   [*] LICENSE: MIT")
        print(f"   [*] AUTHOR: Alexander Mikhailov")
        print(f"\n   [*] SUPPORT: ")
        print(f"          Documentation: https://github.com/alexander-ru/salmonella")
        print(f"          Issues: https://github.com/alexander-ru/salmonella/issues{Fore.RESET}\n")
        sys.exit(0)

    attack_type = sys.argv[1]

    # Проверка корректности типа атаки
    if attack_type not in available_attacks:
        print(banner)
        print(f"\n{Fore.RED}     UNKNOWN ATTACK TYPE: '{attack_type}'{Fore.RESET}")
        print(f"{Fore.YELLOW}     AVAILABLE ATTACKS:{Fore.RESET}")
        print(attacks_table)
        sys.exit(1)

    # Показать help для конкретной атаки
    if len(sys.argv) == 3 and sys.argv[2] in ['-h', '--help']:
        print(banner)

        attack_params = {
            "arp-spoof": f"""{Fore.CYAN}
    ┌───────────────────────────────────────────────────────────────────────────────────────┐
    │                            ARP Spoofing Attack Parameters                             │
    ├───────────────────────────────────────────────────────────────────────────────────────┤
    │  --vic    Victim's IP address                                        (required)       │
    │  --gtw    Gateway IP address                                         (required)       │
    │  --intf   Your network interface (e.g., eth0, Ethernet)                               │
    └───────────────────────────────────────────────────────────────────────────────────────┘{Fore.RESET}{Fore.YELLOW}\n
    [*] Example:
          sudo python3 salmonella.py arp-spoof --vic 192.168.1.10 --gtw 192.168.1.1 --intf eth0""",

            "dhcp-strv": f"""{Fore.CYAN}
    ┌───────────────────────────────────────────────────────────────────────────────────────┐
    │                           DHCP Starvation Attack Parameters                           │
    ├───────────────────────────────────────────────────────────────────────────────────────┤
    │  --cnt    Number of DHCP Discover packets (default 254)                               │
    │  --ip     IP address of the DHCP server (default any)                                 │
    │  --intv   The interval for sending DISCOVER packets (seconds)(default 0)              │
    │  --intf   Your network interface (e.g., eth0, Ethernet)                               │
    └───────────────────────────────────────────────────────────────────────────────────────┘{Fore.RESET}{Fore.YELLOW}\n
    [*] Example:
          sudo python3 salmonella.py dhcp-strv
          sudo python3 salmonella.py dhcp-strv --cnt 100 --intf eth0
          sudo python3 salmonella.py dhcp-strv --ip 192.168.1.1 --cnt 50 --intv 1 --intf eth0""",

            "rog-dhcp": f"""{Fore.CYAN}
    ┌───────────────────────────────────────────────────────────────────────────────────────┐
    │                             Rogue DHCP Attack Parameters                              │
    ├───────────────────────────────────────────────────────────────────────────────────────┤
    │  --ip      IP address of Rogue DHCP server                           (required)       │
    │  --mask    Subnet mask                                               (required)       │
    │  --start   The first IP address from the pool (e.g. 10.10.10.2)      (required)       │
    │  --end     Last IP address from the pool (e.g. 10.10.10.254)         (required)       │
    │  --gtw     The default gateway for clients                           (required)       │
    │  --dns     DNS server address for clients                            (required)       │
    │  --lease   Lease time (seconds)(default 86400)                                        │
    │  --domain  Domain name                                               (required)       │
    │  --intf    Your network interface (e.g., eth0, Ethernet)                              │
    └───────────────────────────────────────────────────────────────────────────────────────┘{Fore.RESET}{Fore.YELLOW}\n
    [*] Example:
          sudo python3 salmonella.py rog-dhcp --ip 192.168.1.100 --mask 255.255.255.0
                                              --start 192.168.1.2 --end 192.168.1.254 
                                              --gtw 192.168.1.100 --dns 77.88.8.8 
                                              --domain salmonella --intf eth0""",

            "dhcp-rls": f"""{Fore.CYAN}
    ┌───────────────────────────────────────────────────────────────────────────────────────┐
    │                        DHCP Release Spoofing Attack Parameters                        │
    ├───────────────────────────────────────────────────────────────────────────────────────┤
    │  --start  The first IP address from the pool (e.g. 10.10.10.2)       (required)       │
    │  --end    Last IP address from the pool (e.g. 10.10.10.254)          (required)       │
    │  --dhcp   IP address of legitimate DHCP server                       (required)       │
    │  --intf   Your network interface (e.g., eth0, Ethernet)                               │
    └───────────────────────────────────────────────────────────────────────────────────────┘{Fore.RESET}{Fore.YELLOW}\n
    [*] Example:
          sudo python3 salmonella.py dhcp-rls --start 172.16.1.2 --end 172.16.1.254 
                                              --dhcp 172.16.1.1 --intf eth0""",

            "cam-overflow": f"""{Fore.CYAN}
    ┌───────────────────────────────────────────────────────────────────────────────────────┐
    │                         CAM Table Overflow Attack Parameters                          │
    ├───────────────────────────────────────────────────────────────────────────────────────┤
    │  --intf   Your network interface (e.g., eth0, Ethernet)                               │
    └───────────────────────────────────────────────────────────────────────────────────────┘{Fore.RESET}{Fore.YELLOW}\n
    [*] Example:
          sudo python3 salmonella.py cam-overflow --intf eth0""",

            "dtp-spoof": f"""{Fore.CYAN}
    ┌───────────────────────────────────────────────────────────────────────────────────────┐
    │                          DTP Spoofing Attack Parameters                               │
    ├───────────────────────────────────────────────────────────────────────────────────────┤
    │  --intf   Your network interface (e.g., eth0, Ethernet)                               │
    └───────────────────────────────────────────────────────────────────────────────────────┘{Fore.RESET}{Fore.YELLOW}\n
    [*] Example:
          sudo python3 salmonella.py dtp-spoof --intf eth0""",

            "eigrp-poison": f"""{Fore.CYAN}
    ┌───────────────────────────────────────────────────────────────────────────────────────┐
    │                           EIGRP Poisoning Attack Parameters                           │
    ├───────────────────────────────────────────────────────────────────────────────────────┤
    │  --net           Destination network                                 (required)       │
    │  --pref          Prefix (e.g. 24)                                    (required)       │
    │  --nh            IP address of next hop (default 0.0.0.0)                             │
    │  --intf          Your network interface (e.g., eth0, Ethernet)                        │
    │  -i, --internal  Use internal EIGRP routes (default)                                  │
    │  -e, --external  Use external EIGRP routes                                            │
    └───────────────────────────────────────────────────────────────────────────────────────┘{Fore.RESET}{Fore.YELLOW}\n
    [*] Example:
          sudo python3 salmonella.py eigrp-poison --net 5.5.5.0 --pref 24 --intf eth0 -e
          sudo python3 salmonella.py eigrp-poison --net 192.168.1.0_172.16.0.0 --pref 24_16 
                                                  --nh 0.0.0.0_172.16.0.1 --intf eth0""",

            "eigrp-k": f"""{Fore.CYAN}
    ┌───────────────────────────────────────────────────────────────────────────────────────┐
    │                       EIGRP Abusing K-values Attack Parameters                        │
    ├───────────────────────────────────────────────────────────────────────────────────────┤
    │  --intf   Your network interface (e.g., eth0, Ethernet)                               │
    └───────────────────────────────────────────────────────────────────────────────────────┘{Fore.RESET}{Fore.YELLOW}\n
    [*] Example:
          sudo python3 salmonella.py eigrp-k --intf eth0""",

            "eigrp-hello": f"""{Fore.CYAN}
    ┌───────────────────────────────────────────────────────────────────────────────────────┐
    │                        EIGRP Hello Flooding Attack Parameters                         │
    ├───────────────────────────────────────────────────────────────────────────────────────┤
    │  --intf   Your network interface (e.g., eth0, Ethernet)                               │
    └───────────────────────────────────────────────────────────────────────────────────────┘{Fore.RESET}{Fore.YELLOW}\n
    [*] Example:
          sudo python3 salmonella.py eigrp-hello --intf eth0""",

            "eigrp-rto": f"""{Fore.CYAN}
    ┌───────────────────────────────────────────────────────────────────────────────────────┐
    │                     EIGRP Routing Table Overflow Attack Parameters                    │
    ├───────────────────────────────────────────────────────────────────────────────────────┤
    │  --intf   Your network interface (e.g., eth0, Ethernet)                               │
    └───────────────────────────────────────────────────────────────────────────────────────┘{Fore.RESET}{Fore.YELLOW}\n
    [*] Example:
          sudo python3 salmonella.py eigrp-rto --intf eth0"""
        }

        if attack_type in attack_params:
            print(attack_params[attack_type])
        sys.exit(0)

    # Парсинг аргументов для выбранной атаки
    parser = argparse.ArgumentParser(add_help=False, exit_on_error=False)

    # Конфигурация аргументов для каждой атаки
    attack_configs = {
        "arp-spoof": [("--vic", {"required": True}), ("--gtw", {"required": True}), ("--intf", {})],
        "dhcp-strv": [("--cnt", {"type": int, "default": 254}), ("--ip", {}), ("--intv", {"type": int, "default": 0}),
                      ("--intf", {})],
        "rog-dhcp": [("--ip", {"required": True}), ("--mask", {"required": True}), ("--start", {"required": True}),
                     ("--end", {"required": True}), ("--gtw", {"required": True}), ("--dns", {"required": True}),
                     ("--lease", {"type": int, "default": 86400}), ("--domain", {"required": True}), ("--intf", {})],
        "dhcp-rls": [("--start", {"required": True}), ("--end", {"required": True}), ("--dhcp", {"required": True}),
                     ("--intf", {})],
        "cam-overflow": [("--intf", {})],
        "dtp-spoof": [("--intf", {})],
        "eigrp-poison": [("--net", {"required": True}), ("--pref", {"required": True}),
                         ("--nh", {"default": "0.0.0.0"}),
                         ("--intf", {}), ("-i", "--internal", {"action": "store_true"}),
                         ("-e", "--external", {"action": "store_true"})],
        "eigrp-k": [("--intf", {})],
        "eigrp-hello": [("--intf", {})],
        "eigrp-rto": [("--intf", {})]
    }

    # Добавление аргументов в парсер
    for arg_config in attack_configs.get(attack_type, []):
        if len(arg_config) == 2:
            parser.add_argument(arg_config[0], **arg_config[1])
        else:  # для флагов с короткими и длинными вариантами
            parser.add_argument(arg_config[0], arg_config[1], **arg_config[2])

    # Парсинг аргументов
    try:
        args = parser.parse_args(sys.argv[2:])
    except (argparse.ArgumentError, SystemExit):
        print(banner)
        print(f"\n{Fore.RED}    ERROR: Invalid arguments for '{attack_type}'{Fore.RESET}")
        print(f"{Fore.YELLOW}    USE 'sudo python3 salmonella.py {attack_type} --help' FOR CORRECT USAGE{Fore.RESET}")
        sys.exit(1)

    # Преобразование аргументов
    attack_args = vars(args)
    attack_args['interface'] = attack_args.pop('intf', None)

    # Специфичные преобразования имен параметров
    param_mappings = {
        "arp-spoof": {"vic": "victim_ip", "gtw": "gateway_ip"},
        "dhcp-strv": {"cnt": "count", "ip": "ip_dhcp", "intv": "interval"},
        "rog-dhcp": {"ip": "ip_addr", "start": "start_ip", "end": "end_ip", "gtw": "gateway", "dns": "dns"},
        "dhcp-rls": {"start": "start_ip", "end": "end_ip", "dhcp": "dhcp_ip"},
        "eigrp-poison": {"net": "network", "pref": "prefix", "nh": "next_hop",
                         "internal": "internal_flag", "external": "external_flag"}
    }

    for old_name, new_name in param_mappings.get(attack_type, {}).items():
        if old_name in attack_args:
            attack_args[new_name] = attack_args.pop(old_name)

    # Запуск атаки (справа - функции атак)
    attack_handlers = {
        "arp-spoof": arp_spoofing,
        "dhcp-strv": dhcp_starvation,
        "rog-dhcp": rogue_dhcp,
        "dhcp-rls": dhcp_release_spoofing,
        "cam-overflow": cam_table_overflow,
        "dtp-spoof": dtp_spoofing,
        "eigrp-poison": eigrp_poisoning,
        "eigrp-k": eigrp_k_abusing,
        "eigrp-hello": eigrp_hello_flooding,
        "eigrp-rto": eigrp_rto
    }

    attack_names = {
        "arp-spoof": "ARP Spoofing",
        "dhcp-strv": "DHCP Starvation",
        "rog-dhcp": "Rogue DHCP",
        "dhcp-rls": "DHCP Release Spoofing",
        "cam-overflow": "CAM Table Overflow",
        "dtp-spoof": "DTP Spoofing",
        "eigrp-poison": "EIGRP Poisoning",
        "eigrp-k": "EIGRP Abusing K-values",
        "eigrp-hello": "EIGRP Hello Flooding",
        "eigrp-rto": "EIGRP Routing Table Overflow"
    }

    print(banner)
    print(f"\n{Fore.YELLOW}    [!] Starting {attack_names[attack_type]} attack...{Fore.RESET}")

    try:
        attack_handlers[attack_type](**attack_args)
    except Exception as e:
        print(f"\n{Fore.RED}    [-] Error during attack: {str(e)}{Fore.RESET}")


if __name__ == "__main__":
    main()
