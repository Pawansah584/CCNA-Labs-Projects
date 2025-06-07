import ipaddress
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv

# ---- Core Logic ----
def get_ip_class(ip):
    first_octet = int(str(ip).split('.')[0])
    if 1 <= first_octet <= 126: return 'A'
    elif 128 <= first_octet <= 191: return 'B'
    elif 192 <= first_octet <= 223: return 'C'
    return 'Unknown'

def to_binary(ip_or_mask):
    return '.'.join(f"{int(octet):08b}" for octet in str(ip_or_mask).split('.'))

def calculate_subnet():
    cidr_input = entry.get().strip()
    try:
        ip_interface = ipaddress.ip_interface(cidr_input)
        network = ip_interface.network
        ip = ip_interface.ip
        hosts = list(network.hosts())
        ip_class = get_ip_class(ip)

        result_text.config(state='normal')
        result_text.delete('1.0', tk.END)
        result_text.insert(tk.END,
            f"IP Address: {ip}\n"
            f"Subnet Mask: {network.netmask}\n"
            f"Wildcard Mask: {network.hostmask}\n"
            f"Network Address: {network.network_address}\n"
            f"Broadcast Address: {network.broadcast_address}\n"
            f"Usable Host Range: {hosts[0]} - {hosts[-1] if hosts else hosts}\n"
            f"Total Hosts: {network.num_addresses}\n"
            f"Usable Hosts: {max(len(hosts), 0)}\n"
            f"IP Class: {ip_class}\n"
            f"Binary IP Address: {to_binary(ip)}\n"
            f"Binary Subnet Mask: {to_binary(network.netmask)}\n"
        )
        result_text.config(state='disabled')

        # Clear previous table
        for i in subnet_table.get_children():
            subnet_table.delete(i)

        # Populate /28 subnets in 192.168.100.0/24
        parent_network = ipaddress.ip_network(f"{ip}/24", strict=False)
        subnets = list(parent_network.subnets(new_prefix=28))
        for sn in subnets:
            h = list(sn.hosts())
            subnet_table.insert('', 'end', values=(
                str(sn.network_address),
                f"{h[0]} - {h[-1]}" if h else "N/A",
                str(sn.broadcast_address)
            ))

    except Exception as e:
        messagebox.showerror("Invalid Input", f"Error: {e}")

def export_to_csv():
    file_path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[("CSV files", "*.csv")])
    if not file_path:
        return
    with open(file_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(columns)
        for row_id in subnet_table.get_children():
            row = subnet_table.item(row_id)['values']
            writer.writerow(row)
    messagebox.showinfo("Exported", f"Data exported to {file_path}")

def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(result_text.get("1.0", tk.END))
    messagebox.showinfo("Copied", "Subnet information copied to clipboard.")

def toggle_dark_mode():
    global is_dark
    is_dark = not is_dark
    bg = "#1e1e1e" if is_dark else "#f0f4f8"
    fg = "#ffffff" if is_dark else "#000000"
    entry_bg = "#2d2d2d" if is_dark else "#ffffff"

    root.configure(bg=bg)
    frame_top.configure(bg=bg)
    result_frame.configure(bg=bg)
    frame_table.configure(bg=bg)

    for widget in frame_top.winfo_children():
        if isinstance(widget, tk.Label) or isinstance(widget, tk.Button):
            widget.configure(bg=bg, fg=fg)
        elif isinstance(widget, tk.Entry):
            widget.configure(bg=entry_bg, fg=fg, insertbackground=fg)

    label_table.configure(bg=bg, fg=fg)
    result_text.configure(bg=entry_bg, fg=fg)
    style.configure("Treeview", background=entry_bg, foreground=fg, fieldbackground=entry_bg)
    style.configure("Treeview.Heading", background="#333" if is_dark else "#ddd", foreground=fg)

# --- New function to copy clicked IP from table ---
def on_table_click(event):
    item_id = subnet_table.identify_row(event.y)
    column = subnet_table.identify_column(event.x)

    if item_id and column:
        col_index = int(column.replace('#', '')) - 1
        values = subnet_table.item(item_id, 'values')
        if 0 <= col_index < len(values):
            ip_to_copy = values[col_index]
            root.clipboard_clear()
            root.clipboard_append(ip_to_copy)
            messagebox.showinfo("Copied", f"Copied to clipboard:\n{ip_to_copy}")

# ---- GUI Setup ----
root = tk.Tk()
root.title("IPv4 Subnet Calculator")
root.geometry("1020x800")
root.configure(bg="#f0f4f8")
is_dark = False

font_main = ("Segoe UI", 11)
font_bold = ("Segoe UI", 11, "bold")
font_heading = ("Segoe UI", 12, "bold")

# ---- Input Frame ----
frame_top = tk.Frame(root, bg="#f0f4f8")
frame_top.pack(pady=10)

tk.Label(frame_top, text="Enter IP/CIDR (e.g., 192.168.100.100/28):", font=font_bold, bg="#f0f4f8").pack()
entry = tk.Entry(frame_top, width=35, font=font_main)
entry.pack(pady=5)
tk.Button(frame_top, text="Calculate", command=calculate_subnet, font=font_bold, bg="#d1e7ff").pack(pady=5)

btn_frame = tk.Frame(root, bg="#f0f4f8")
btn_frame.pack(pady=5)
tk.Button(btn_frame, text="Copy to Clipboard", command=copy_to_clipboard, font=font_main, bg="#ccf2ff").pack(side="left", padx=5)
tk.Button(btn_frame, text="Export to CSV", command=export_to_csv, font=font_main, bg="#ccffcc").pack(side="left", padx=5)
tk.Button(btn_frame, text="Toggle Dark Mode", command=toggle_dark_mode, font=font_main, bg="#e6e6e6").pack(side="left", padx=5)

# ---- Result Display ----
result_frame = tk.Frame(root, bg="#f0f4f8")
result_frame.pack(pady=10, fill="x", padx=20)

result_text = tk.Text(result_frame, wrap="word", height=10, font=font_main, state='disabled', bg="#ffffff")
result_text.pack(side="left", fill="both", expand=True)
result_scroll = ttk.Scrollbar(result_frame, command=result_text.yview)
result_scroll.pack(side="right", fill="y")
result_text.config(yscrollcommand=result_scroll.set)

# ---- Subnet Table ----
label_table = tk.Label(root, text="All /28 Subnets in 192.168.100.0/24", font=font_heading, bg="#f0f4f8")
label_table.pack(pady=10)

frame_table = tk.Frame(root, bg="#f0f4f8")
frame_table.pack(pady=10, fill="both", expand=True, padx=20)

columns = ('Network Address', 'Usable Host Range', 'Broadcast Address')
subnet_table = ttk.Treeview(frame_table, columns=columns, show='headings', height=10)

style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="#ffffff", foreground="#000000", rowheight=30, fieldbackground="#ffffff", font=font_main)
style.configure("Treeview.Heading", font=font_heading)
style.map('Treeview', background=[('selected', '#b3d9ff')])

for col in columns:
    subnet_table.heading(col, text=col)
    subnet_table.column(col, width=320, anchor='center')

scrollbar_table = ttk.Scrollbar(frame_table, orient="vertical", command=subnet_table.yview)
subnet_table.configure(yscrollcommand=scrollbar_table.set)
scrollbar_table.pack(side='right', fill='y')
subnet_table.pack(fill='both', expand=True)

# Bind left mouse click on the table to the copy function
subnet_table.bind("<ButtonRelease-1>", on_table_click)

root.mainloop()
