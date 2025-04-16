import tkinter as tk
from tkinter import ttk, filedialog, messagebox
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
packets_data = []  # (row_data, packet_dump)

search_index = None  # for searching inside text widget

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
    full_packet_text = str(packet.show(dump=True))
    packets_data.append((row, full_packet_text))

    status_var.set(f"Packets Captured: {packet_count} | Filter: {filter_protocol.upper() if filter_protocol else 'ALL'}")

    def insert_row():
        tag = proto.lower() if proto.lower() in ['tcp', 'udp', 'icmp'] else 'other'
        iid = tree.insert('', 'end', values=row, tags=(tag,))
        tree.see(iid)

    tree.after(0, insert_row)

# ===============================
# Controls
# ===============================
def start_sniffing():
    global sniffing, packet_count, packets_data
    sniffing = True
    paused_btn.config(state=tk.NORMAL)
    export_btn.config(state=tk.NORMAL)
    save_btn.config(state=tk.NORMAL)
    packet_count = 0
    packets_data = []
    tree.delete(*tree.get_children())
    details_text.delete("1.0", tk.END)
    threading.Thread(target=lambda: sniff(prn=process_packet, store=False, stop_filter=lambda x: not sniffing), daemon=True).start()

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
        messagebox.showinfo("Export", "No packets to export.")
        return
    path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if path:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(['#', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
            for row, _ in packets_data:
                writer.writerow(row)

def on_row_select(event):
    selected = tree.focus()
    if not selected:
        return
    idx = tree.index(selected)
    if idx >= len(packets_data):
        return
    _, detail = packets_data[idx]
    details_text.delete("1.0", tk.END)
    details_text.insert(tk.END, detail)

def save_packet_dump():
    content = details_text.get("1.0", tk.END).strip()
    if not content:
        messagebox.showinfo("Save Dump", "No packet detail to save.")
        return
    path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("Success", f"Packet dump saved to {path}")

# ===============================
# Search Functions
# ===============================
def search_text(forward=True):
    global search_index
    details_text.tag_remove("highlight", "1.0", tk.END)
    query = search_var.get().strip()
    if not query:
        return
    start_pos = search_index if search_index else "1.0"
    pos = details_text.search(query, start_pos, tk.END if forward else "1.0", nocase=True, backwards=not forward)
    if not pos:
        messagebox.showinfo("Search", "No more matches.")
        return
    end = f"{pos}+{len(query)}c"
    details_text.tag_add("highlight", pos, end)
    details_text.tag_config("highlight", background="green")
    search_index = end if forward else pos

def clear_search():
    global search_index
    search_index = None
    details_text.tag_remove("highlight", "1.0", tk.END)
    search_var.set("")

# ===============================
# UI Setup
# ===============================
root = tk.Tk()
root.title("Wireshark Lite - Packet Sniffer")
root.geometry("1000x750")
root.configure(bg="black")

status_var = tk.StringVar(value="Packets Captured: 0 | Filter: ALL")
status_bar = tk.Label(root, textvariable=status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W, bg="black", fg="white")
status_bar.pack(side=tk.BOTTOM, fill=tk.X)

# Filter Frame
filter_frame = tk.Frame(root, bg="black")
filter_frame.pack(fill=tk.X, padx=5, pady=5)

tk.Label(filter_frame, text="Filter Protocol:", fg="white", bg="black").pack(side=tk.LEFT, padx=(0, 5))
protocol_options = ['All', 'TCP', 'UDP', 'ICMP']
filter_var = tk.StringVar(value='All')
filter_menu = ttk.Combobox(filter_frame, textvariable=filter_var, values=protocol_options, state='readonly')
filter_menu.pack(side=tk.LEFT)

def set_filter(event=None):
    global filter_protocol
    sel = filter_var.get().strip().lower()
    filter_protocol = '' if sel == 'all' else sel

filter_menu.bind("<<ComboboxSelected>>", set_filter)

# Tree View
columns = ('#', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
tree = ttk.Treeview(root, columns=columns, show='headings')
tree.tag_configure('tcp', background='#ffd6d6')
tree.tag_configure('udp', background='#d6f0ff')
tree.tag_configure('icmp', background='#d6ffd6')
tree.tag_configure('other', background='#eeeeee')
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=130 if col != 'Info' else 500)
tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
tree.bind("<<TreeviewSelect>>", on_row_select)

scrollbar = ttk.Scrollbar(tree, orient="vertical", command=tree.yview)
tree.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side='right', fill='y')

# Detail Pane
detail_frame = tk.Frame(root)
detail_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

details_text = tk.Text(detail_frame, height=10, bg="black", fg="white", font=("Courier", 10))
details_text.pack(fill=tk.BOTH, expand=True)

# Search controls
search_control = tk.Frame(root, bg="black")
search_control.pack(fill=tk.X, padx=10)

tk.Label(search_control, text="Search:", fg="white", bg="black").pack(side=tk.LEFT)
search_var = tk.StringVar()
tk.Entry(search_control, textvariable=search_var, width=30).pack(side=tk.LEFT, padx=5)

tk.Button(search_control, text="Find Next", command=lambda: search_text(True)).pack(side=tk.LEFT, padx=2)
tk.Button(search_control, text="Find Prev", command=lambda: search_text(False)).pack(side=tk.LEFT, padx=2)
tk.Button(search_control, text="Clear Search ", command=clear_search).pack(side=tk.LEFT, padx=2)

# Buttons
btn_frame = tk.Frame(root, bg="black")
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Start Sniffing", command=start_sniffing, bg="green", fg="white").pack(side=tk.LEFT, padx=10)
tk.Button(btn_frame, text="Stop Sniffing", command=stop_sniffing, bg="red", fg="white").pack(side=tk.LEFT, padx=10)

pause_var = tk.StringVar(value="Pause")
paused_btn = tk.Button(btn_frame, textvariable=pause_var, command=toggle_pause, bg="orange", fg="black", state=tk.DISABLED)
paused_btn.pack(side=tk.LEFT, padx=10)

export_btn = tk.Button(btn_frame, text="Export CSV", command=export_to_csv, bg="blue", fg="white", state=tk.DISABLED)
export_btn.pack(side=tk.LEFT, padx=10)

save_btn = tk.Button(btn_frame, text="Save Dump", command=save_packet_dump, bg="purple", fg="white", state=tk.DISABLED)
save_btn.pack(side=tk.LEFT, padx=10)

root.mainloop()
