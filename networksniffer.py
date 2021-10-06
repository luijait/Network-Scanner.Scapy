#! /usr/bin/env python3

from collections import Counter
from scapy.all import sniff
import sys

ip = sys.argv[1]
num_paquetes = sys.argv[2]

contadordepaquetes = Counter()

def sniffer(packet):
    paquete = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    contadordepaquetes.update([paquete])
    return f"Paquete numero: #{sum(contadordepaquetes.values())}: Viene de {packet[0][1].src} ==> {packet[0][1].dst} Para este destino"


sniff(filter="ip and (host "+ (ip) +")", prn=sniffer, count=int(num_paquetes))
print("\n".join(f"{f'{paquete[0]} <--> {paquete[1]}'}: {count}" for paquete, count in contadordepaquetes.items()))
