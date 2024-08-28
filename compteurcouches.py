from scapy.config import conf
from scapy.layers.all import *
from scapy.all import *

##################

listProtos=[layer.__name__ for layer in conf.layers]
nbPackets=int(input('Combien de paquet souhaitez-vous sniffer ?'))
coucheASniffer=input('Quelle couche souhaitez-vous capturer ?')
if coucheASniffer in listProtos:
    print("Oui")
else: 
    print("Non")
show_interfaces()
indexCarte=int(input('Quel est l\'index de la carte à capturer  ?'))
packets=sniff(count=nbPackets,iface=dev_from_index(indexCarte))
compteur=0
for packet in packets :
    if(packet.haslayer(coucheASniffer)):
        compteur+=1

print('La capture contient '+str(compteur)+' paquets du type '+coucheASniffer)