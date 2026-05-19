import customtkinter as ctk
from tkinter import ttk
from scapy.all import sniff
import threading
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from datetime import datetime
import csv
from tkinter import filedialog
from tkinter import messagebox
from tkinter.simpledialog import askstring

def kolon_filtrele(kolon):
    deger = askstring("Filtre", f"{kolon} için filtre gir:")
    if deger:
        column_filters[kolon] = deger.lower()
    else:
        column_filters.pop(kolon, None)

    tabloyu_guncelle()

def seciliyi_kopyala(event=None):
    secili = tree.selection()
    if not secili:
        return

    satir = tree.item(secili[0])["values"]
    metin = " | ".join(map(str, satir))

    app.clipboard_clear()
    app.clipboard_append(metin)

def tabloya_ekle(veri):

    if filtre != "ALL" and veri["proto"] != filtre:
        return

    aranan = arama_var.get().lower()
    if aranan:
        if (aranan not in veri["src"].lower() and
            aranan not in veri["dst"].lower() and
            aranan not in veri["info"].lower()):
            return

    tree.insert("", "end",
        values=(
            veri["no"],
            veri["zaman"],
            veri["src"],
            veri["dst"],
            veri["proto"],
            veri["port"],
            veri["length"],
            veri["info"]
        ),
        tags=(veri["proto"],)
    )

    tree.yview_moveto(1)

def filtre_degistir(f):
    global filtre
    filtre = f
    tabloyu_guncelle()

def sniff_baslat():
    global calisiyor
    sniff(prn=paket_yakala, store=False, stop_filter=lambda x: not calisiyor)
    
def paket_yakala(packet):
    try:
        zaman = datetime.now().strftime("%H:%M:%S")
        proto = "OTHER"
        src = ""
        dst = ""
        info = ""
        port = ""
        
        if packet.haslayer(ARP):
            proto = "ARP"
            src = packet[ARP].psrc
            dst = packet[ARP].pdst

            if packet[ARP].op == 1:
                info = f"Who has {dst}?"
            else:
                info = f"{src} is at MAC"

        elif packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst

            
            if packet.haslayer(TCP):
                proto = "TCP"
                port = f"{packet[TCP].sport}->{packet[TCP].dport}"
                
                if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    proto = "HTTPS"
                    info = "Secure Web Traffic"
                else:
                    info = port

            elif packet.haslayer(UDP):
                proto = "UDP"
                port = f"{packet[UDP].sport} → {packet[UDP].dport}"
                info= port
                
            elif packet.haslayer(ICMP):
                proto = "ICMP"
                info = "Ping"
            
            elif packet.haslayer(DNS):
                proto = "DNS"
                try:
                    qname = packet[DNS].qd.qname.decode()
                    info = f"DNS Query: {qname}"
                except:
                    info = "DNS Packet"
        else:
            return

        length = len(packet)

        global sayac   
        sayac += 1
        veri = {
            "no": sayac,
            "zaman": zaman,
            "src": src,
            "dst": dst,
            "proto": proto,
            "port": port,
            "length": length,
            "info": info
        }

        tum_veriler.append(veri)
        app.after(0, lambda: tabloya_ekle(veri))
        

    except:
        pass

def tabloyu_guncelle():
    for item in tree.get_children():
        tree.delete(item)

    aranan = arama_var.get().lower()
    
    for veri in tum_veriler:

        if filtre != "ALL" and veri["proto"] != filtre:
            continue

        if aranan:
            if (aranan not in veri["src"].lower() and
                aranan not in veri["dst"].lower() and
                aranan not in veri["info"].lower()):
                continue
        for kolon, deger in column_filters.items():
            if deger not in str(veri[kolon]).lower():
                break
        else:

            tree.insert("", "end",
                values=(
                    veri["no"],
                    veri["zaman"],
                    veri["src"],
                    veri["dst"],
                    veri["proto"],
                    veri["port"],
                    veri["length"],
                    veri["info"] ),
                tags=(veri["proto"],))
          
def baslat():
    global calisiyor
    calisiyor = True
    
    btn_baslat.configure(state="disabled")
    btn_durdur.configure(state="normal")
    
    threading.Thread(target=sniff_baslat, daemon=True).start()

def durdur():
    global calisiyor

    if messagebox.askyesno("Onay", "Durdurmak istiyor musunuz?"):
        calisiyor = False

        btn_baslat.configure(state="normal")
        btn_durdur.configure(state="disabled")

def temizle():
    global tum_veriler
    tum_veriler = []
    tabloyu_guncelle()
    global sayac
    sayac = 0
    
def kaydet():
    dosya = filedialog.asksaveasfilename(defaultextension=".csv")

    if dosya:
        with open(dosya, "w", newline="") as f:
            writer = csv.writer(f)

            writer.writerow(["Time", "Source", "Destination", "Protocol", "Length", "Info"])

            for veri in tum_veriler:
                writer.writerow([
                    veri["zaman"],
                    veri["src"],
                    veri["dst"],
                    veri["proto"],
                    veri["length"],
                    veri["info"]
                ])

def cikis():
    if messagebox.askyesno("Çıkış", "Programı kapatmak istiyor musunuz?"):
        app.destroy()

calisiyor = False
tum_veriler = []
filtre = "ALL"
sayac = 0
column_filters = {}

ctk.set_appearance_mode("dark")
app = ctk.CTk()
app.title("Network Monitor")
app.geometry("1000x600")

baslik = ctk.CTkLabel(app, text="Network Traffic Monitor", font=("Arial", 20))
baslik.pack(pady=20)

filtre_frame = ctk.CTkFrame(app)
filtre_frame.pack(pady=5)
protokoller = ["ALL", "TCP", "UDP", "ICMP", "ARP", "DNS", "HTTPS"]

arama_var = ctk.StringVar()

arama_entry = ctk.CTkEntry(app, placeholder_text="Ara (IP / Info)", textvariable=arama_var)
arama_entry.pack(pady=5)
arama_entry.bind("<KeyRelease>", lambda e: tabloyu_guncelle())

for i, p in enumerate(protokoller):
    ctk.CTkButton(
        filtre_frame,
        text=p,
        width=70,
        command=lambda x=p: filtre_degistir(x)
    ).grid(row=0, column=i, padx=5)
    
buton_frame = ctk.CTkFrame(app)
buton_frame.pack(pady=10)

btn_baslat = ctk.CTkButton(buton_frame, text="Başlat", command=baslat)
btn_baslat.grid(row=0, column=0, padx=10)

btn_durdur = ctk.CTkButton(buton_frame, text="Durdur", command=durdur, state="disabled")
btn_durdur.grid(row=0, column=1, padx=10)

btn_temizle = ctk.CTkButton(buton_frame, text="Temizle",command=temizle)
btn_temizle.grid(row=0, column=2, padx=10)

btn_kaydet = ctk.CTkButton(buton_frame, text="Kaydet", command=kaydet)
btn_kaydet.grid(row=0, column=3, padx=10)

btn_cikis = ctk.CTkButton(buton_frame, text="Çıkış", command=cikis)
btn_cikis.grid(row=0, column=4, padx=10)

frame_table = ctk.CTkFrame(app)
frame_table.pack(pady=10, fill="both", expand=True)

tree = ttk.Treeview(
    frame_table,
    columns=("no", "time", "src", "dst", "proto","port", "len", "info"),
    show="headings"
)
tree.bind("<Control-c>", seciliyi_kopyala)
tree.tag_configure("TCP", background="#003366", foreground="white")
tree.tag_configure("UDP", background="#004d00", foreground="white")
tree.tag_configure("ICMP", background="#4b0082", foreground="white")
tree.tag_configure("ARP", background="#ff9900", foreground="black")
tree.tag_configure("DNS", background="#cccc00", foreground="black")
tree.tag_configure("HTTPS", background="#660033", foreground="white")

tree.heading("no", text="#")
tree.heading("time", text="Time")
tree.heading("src", text="Source", command=lambda: kolon_filtrele("src"))
tree.heading("dst", text="Destination", command=lambda: kolon_filtrele("dst"))
tree.heading("proto", text="Protocol", command=lambda: kolon_filtrele("proto"))
tree.heading("port", text="Port", command=lambda: kolon_filtrele("port"))
tree.heading("len", text="Length")
tree.heading("info", text="Info")

tree.column("no", width=40)
tree.column("time", width=80)
tree.column("src", width=150)
tree.column("dst", width=150)
tree.column("proto", width=80)
tree.column("port", width=50)
tree.column("len", width=60)
tree.column("info", width=300)

scrollbar = ttk.Scrollbar(frame_table, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=scrollbar.set)

tree.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

app.mainloop() 