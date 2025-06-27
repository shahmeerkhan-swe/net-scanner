import tkinter as tk 
from tkinter import ttk
from tkinter import messagebox
import json 
from datetime import datetime 
from tabulate import tabulate 
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from main import scan_network, get_hostname, get_vendor

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

    start_total = time.time()

    start_scan = time.time()
    devices = scan_network("192.168.1.0/24")
    end_scan = time.time()
    scan_duration = end_scan - start_scan
    print(f"scan_network took {scan_duration:.2f} seconds")

    start_resolve = time.time()
    devices = resolve_device_info(devices)
    end_resolve = time.time()
    resolve_duration = end_resolve - start_resolve
    print(f"Hostname/Vendor resolution took {resolve_duration:.2f} seconds")

    def update_gui():
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
