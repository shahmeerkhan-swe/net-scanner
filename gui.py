import tkinter as tk 
from tkinter import ttk
from tkinter import messagebox
import json 
import ipaddress
from datetime import datetime 
from tabulate import tabulate 
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from main import scan_network, get_hostname, get_vendor

previous_devices = set()

def resolve_device_info(devices):
    def resolve(device):
        device['hostname'] = get_hostname(device['ip'])
        device['vendor'] = get_vendor(device['mac'])
        return device
    
    with ThreadPoolExecutor(max_workers=20) as executor: 
        devices = list(executor.map(resolve, devices))
    return devices

def export_to_json(devices): 
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"scan_{timestamp}.json"
    data = []

    for device in devices:
        entry = {
            "IP": device['ip'],
            "MAC": device['mac'],
            "Hostname": get_hostname(device['ip']),
            "Vendor": get_vendor(device['mac'])
        }
        data.append(entry)

    with open(filename, 'w') as f: 
        json.dump(data, f, indent=4)
    return filename

def start_scan():
    scan_button.config(state='disabled')
    export_check.config(state='disabled')
    loading_label.config(text="Scanning network...")

    thread = threading.Thread(target=run_scan)
    thread.start()

def run_scan():

    ip_range = ip_range_var.get().strip()
    if not ip_range: 
        ip_range = "192.168.1.0/24"

    try:
        ip_range_obj = ipaddress.ip_network(ip_range, strict=False)
    except ValueError: 
        root.after(0, lambda: messagebox.showerror(
            "Invalid IP Range", "Please enter a valid CIDR IP Range (e.g., 192.168.1.0/24)."
        ))
        root.after(0, lambda: loading_label.config(state='normal'))
        root.after(0, lambda: scan_button.config(state='normal'))
        root.after(0, lambda: export_check.config(state='normal'))
        return



    start_total = time.time()

    start_scan_time = time.time()
    devices = scan_network(str(ip_range_obj))
    end_scan = time.time()
    scan_duration = end_scan - start_scan_time
    print(f"scan_network took {scan_duration:.2f} seconds")

    start_resolve = time.time()
    devices = resolve_device_info(devices)
    end_resolve = time.time()
    resolve_duration = end_resolve - start_resolve
    print(f"Hostname/Vendor resolution took {resolve_duration:.2f} seconds")

    def update_gui():

        global previous_devices
        new_devices = set((d['ip'], d['mac']) for d in devices)

        if previous_devices and (unknown := new_devices - previous_devices):
            for ip, mac in unknown: 
                hostname = get_hostname(ip)
                vendor = get_vendor(mac)
                messagebox.showwarning("New Device Detected", f"IP: {ip}\nMAC: {mac}\nHostname: {hostname}\nVendor: {vendor}")

        previous_devices = new_devices

        for row in result_table.get_children():
            result_table.delete(row)

        for device in devices:
            hostname = device.get('hostname', '')
            vendor = device.get('vendor', '')
            result_table.insert('', 'end', values=(device['ip'], device['mac'], hostname, vendor))

        if export_var.get(): 
            filename = export_to_json(devices)
            messagebox.showinfo("Exported", f"Scan results saved to: \n{filename}")


        end_total = time.time()
        total_duration = end_total - start_total

        loading_label.config(text=f"Scan completed in {total_duration:.2f} seconds")
        scan_button.config(state='normal')
        export_check.config(state='normal')

        if auto_var.get():
            root.after(30000, start_scan) # Refresh after 30 seconds

        print(f"Total scan + resolve + update_gui time: {total_duration:.2f} seconds")

    root.after(0, update_gui)

# Create a main window
root = tk.Tk()
root.title("Network Scanner")
root.geometry("700x400")

# Frame for buttons and options
top_frame = ttk.Frame(root)
top_frame.pack(pady=10)

# Scan button
scan_button = ttk.Button(top_frame, text="Scan Network", command=start_scan)
scan_button.pack(side='left', padx=10)

export_var = tk.BooleanVar()
export_check = ttk.Checkbutton(top_frame, text="Export to JSON", variable=export_var)
export_check.pack(side='left')

# Auto scan checkbox
auto_var = tk.BooleanVar()
auto_check = ttk.Checkbutton(top_frame, text="Auto-Scan", variable=auto_var)
auto_check.pack(side='left')

# IP Range Input
range_frame = ttk.Frame(root)
range_frame.pack(pady=5)

ttk.Label(range_frame, text="IP Range (CIDR):").pack(side='left')
ip_range_var = tk.StringVar(value="192.168.1.0/24") # Default value
ip_entry = ttk.Entry(range_frame, textvariable=ip_range_var, width=25)
ip_entry.pack(side='left', padx=5)

# Loading label
loading_label = ttk.Label(root, text="", foreground="blue")
loading_label.pack(pady=5)

# Results table
columns = ("IP Address", "MAC Address", "Hostname", "Vendor")
result_table = ttk.Treeview(root, columns=columns, show='headings')

for col in columns:
    result_table.heading(col, text=col)
    result_table.column(col, width=160)

result_table.pack(expand=True, fill='both', pady=10)

# Scrollbar functionality
scrollbar = ttk.Scrollbar(root, orient='vertical', command=result_table.yview)
result_table.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side='right', fill='y')

root.mainloop()
