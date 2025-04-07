import tkinter as tk
from tkinter import ttk, filedialog
from scapy.all import sniff
import threading
import csv

# ===============================
# Global variables
# ===============================
sniffing = False
paused = False
packet_count = 0
filter_protocol = ""
status_var = None
filter_var = None
packets_data = []  # Store all rows for CSV export

# ===============================
# Packet processing function
# ===============================
def process_packet(packet):
    global packet_count, packets_data

    if paused:
        return

    proto = ''
    if packet.haslayer('TCP'):
        proto = 'TCP'
    elif packet.haslayer('UDP'):
        proto = 'UDP'
    elif packet.haslayer('ICMP'):
        proto = 'ICMP'
    else:
        proto = packet.name

    if filter_protocol and proto.lower() != filter_protocol:
        return

    src = packet[0].src if hasattr(packet[0], 'src') else "N/A"
    dst = packet[0].dst if hasattr(packet[0], 'dst') else "N/A"
    length = len(packet)
    info = packet.summary()

    packet_count += 1
    row = (packet_count, src, dst, proto, length, info)
    packets_data.append(row)

    status_text = f"Packets Captured: {packet_count} | Filter: {filter_protocol.upper() if filter_protocol else 'ALL'}"
    status_var.set(status_text)

    def insert_row():
        tag = proto.lower() if proto.lower() in ['tcp', 'udp', 'icmp'] else 'other'
        iid = tree.insert('', 'end', values=row, tags=(tag,))
        tree.see(iid)

    tree.after(0, insert_row)

# ===============================
# Sniffing control
# ===============================
def start_sniffing():
    global sniffing, packet_count, packets_data
    sniffing = True
    paused_btn.config(state=tk.NORMAL)
    export_btn.config(state=tk.NORMAL)
    packet_count = 0
    packets_data = []

    for item in tree.get_children():
        tree.delete(item)

    threading.Thread(target=lambda: sniff(
        prn=process_packet,
        store=False,
        stop_filter=lambda x: not sniffing
    ), daemon=True).start()

def stop_sniffing():
    global sniffing
    sniffing = False
    paused_btn.config(state=tk.DISABLED)
    pause_var.set("Pause")

def toggle_pause():
    global paused
    paused = not paused
    pause_var.set("Resume" if paused else "Pause")

def export_to_csv():
    if not packets_data:
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not file_path:
        return
    with open(file_path, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['#', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
        writer.writerows(packets_data)

# ===============================
# UI Setup
# ===============================
root = tk.Tk()
root.title("Mini Wireshark - Packet Sniffer")
root.geometry("1000x600")
root.configure(bg="black")

status_var = tk.StringVar()
status_var.set("Packets Captured: 0 | Filter: ALL")
status_bar = tk.Label(root, textvariable=status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W, bg="black", fg="white")
status_bar.pack(side=tk.BOTTOM, fill=tk.X)

filter_frame = tk.Frame(root, bg="black")
filter_frame.pack(fill=tk.X, padx=5, pady=5)

# Protocol filter only
tk.Label(filter_frame, text="Filter Protocol:", fg="white", bg="black").pack(side=tk.LEFT, padx=(0, 5))
protocol_options = ['All', 'TCP', 'UDP', 'ICMP']
filter_var = tk.StringVar(value='All')
filter_menu = ttk.Combobox(filter_frame, textvariable=filter_var, values=protocol_options, state='readonly')
filter_menu.pack(side=tk.LEFT)

def set_filter(event=None):
    global filter_protocol
    selection = filter_var.get().strip().lower()
    filter_protocol = '' if selection == 'all' else selection
    print(f"[INFO] Filter set to: {selection}")

filter_menu.bind("<<ComboboxSelected>>", set_filter)

columns = ('#', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
tree = ttk.Treeview(root, columns=columns, show='headings')
tree.tag_configure('tcp', background='#ffd6d6')
tree.tag_configure('udp', background='#d6f0ff')
tree.tag_configure('icmp', background='#d6ffd6')
tree.tag_configure('other', background='#eeeeee')

for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=130 if col != 'Info' else 400)

tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

scrollbar = ttk.Scrollbar(tree, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side='right', fill='y')

btn_frame = tk.Frame(root, bg="black")
btn_frame.pack(pady=10)

start_btn = tk.Button(btn_frame, text="Start Sniffing", command=start_sniffing, bg="green", fg="white")
start_btn.pack(side=tk.LEFT, padx=10)

stop_btn = tk.Button(btn_frame, text="Stop Sniffing", command=stop_sniffing, bg="red", fg="white")
stop_btn.pack(side=tk.LEFT, padx=10)

pause_var = tk.StringVar(value="Pause")
paused_btn = tk.Button(btn_frame, textvariable=pause_var, command=toggle_pause, bg="orange", fg="black", state=tk.DISABLED)
paused_btn.pack(side=tk.LEFT, padx=10)

export_btn = tk.Button(btn_frame, text="Export CSV", command=export_to_csv, bg="blue", fg="white", state=tk.DISABLED)
export_btn.pack(side=tk.LEFT, padx=10)

root.mainloop()
