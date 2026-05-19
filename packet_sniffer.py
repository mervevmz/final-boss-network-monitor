from scapy.all import sniff

def paket_yakala(callback):
    sniff(prn=callback, store=False)
