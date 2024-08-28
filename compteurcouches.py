from scapy.config import conf
from scapy.layers.all import *
from scapy.all import *

##################

listProtos=[layer.__name__ for layer in conf.layers]
nbPackets=int(input('Combien de paquet souhaitez-vous sniffer ?'))
coucheASniffer=input('Quelle couche souhaitez-vous capturer ?')
try:
    ## Check que la réponse est correcte
    if not coucheASniffer in listProtos:
        raise ValueError
        
    show_interfaces() 
    indexCarte=int(input('Quel est l\'index de la carte à capturer  ?'))
    packets=sniff(count=nbPackets,iface=dev_from_index(indexCarte))
    compteur=0
    compteurTotal=0
    for packet in packets :
        compteurTotal+=1
        if(packet.haslayer(coucheASniffer)):
            compteur+=1

    print('La capture contient '+str(compteur)+' paquets du type '+coucheASniffer)
    pourcentage = (compteur/compteurTotal)*100
    print('Cela représente '+str(pourcentage)+"% des requêtes totales.")
except ValueError as e:
    print("La couche que vous souhaitez capturer n'existe pas. Le script s'interrompt.")
    SystemExit(1)