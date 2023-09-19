from scapy.all import *

# Vyberte síťové rozhraní, na kterém chcete zachytávat pakety
interface_name = "Ethernet"  # Změňte na název vašeho rozhraní

# Hlavní smyčka pro zachytávání datových paketů na úrovni 3
def packet_callback(packet):
    print(packet.summary())

# Spusťte zachytávání na zvoleném rozhraní na úrovni 3
sniff(iface=interface_name, prn=packet_callback, lfilter=lambda x: x.haslayer(IP))
