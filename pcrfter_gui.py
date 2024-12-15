import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import *

def send_packet(packet, count):
    try:
        for _ in range(count):
            sendp(packet)
        messagebox.showinfo("Success", "Packet(s) sent successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send packet: {e}")

def craft_layer_2():
    def send():
        src_mac = get_if_hwaddr(conf.iface)
        dst_mac = dst_mac_entry.get()
        payload = payload_entry.get()
        count = int(packet_count_entry.get())

        if not dst_mac:
            messagebox.showerror("Error", "Destination MAC address is required!")
            return

        packet = Ether(src=src_mac, dst=dst_mac)
        if payload:
            packet = packet / Raw(load=payload)

        send_packet(packet, count)

    layer_2_window = tk.Toplevel()
    layer_2_window.title("Craft Layer 2 Packet")

    tk.Label(layer_2_window, text="Destination MAC Address:").grid(row=0, column=0, padx=10, pady=10)
    dst_mac_entry = tk.Entry(layer_2_window, width=30)
    dst_mac_entry.grid(row=0, column=1, padx=10, pady=10)

    tk.Label(layer_2_window, text="Payload (optional):").grid(row=1, column=0, padx=10, pady=10)
    payload_entry = tk.Entry(layer_2_window, width=30)
    payload_entry.grid(row=1, column=1, padx=10, pady=10)

    tk.Label(layer_2_window, text="Number of Packets:").grid(row=2, column=0, padx=10, pady=10)
    packet_count_entry = tk.Entry(layer_2_window, width=10)
    packet_count_entry.insert(0, "1")
    packet_count_entry.grid(row=2, column=1, padx=10, pady=10)

    send_button = tk.Button(layer_2_window, text="Send", command=send)
    send_button.grid(row=3, column=0, columnspan=2, pady=20)

def craft_layer_3():
    def send():
        dst_ip = dst_ip_entry.get()
        protocol = protocol_combobox.get().upper()
        payload = payload_entry.get()
        count = int(packet_count_entry.get())

        if not dst_ip:
            messagebox.showerror("Error", "Destination IP address is required!")
            return

        packet = IP(dst=dst_ip)
        if protocol == "ICMP":
            packet = packet / ICMP()
        elif protocol == "TCP":
            sport = int(src_port_entry.get())
            dport = int(dst_port_entry.get())
            packet = packet / TCP(sport=sport, dport=dport)
        elif protocol == "UDP":
            sport = int(src_port_entry.get())
            dport = int(dst_port_entry.get())
            packet = packet / UDP(sport=sport, dport=dport)

        if payload:
            packet = packet / Raw(load=payload)

        send_packet(packet, count)

    layer_3_window = tk.Toplevel()
    layer_3_window.title("Craft Layer 3 Packet")

    tk.Label(layer_3_window, text="Destination IP Address:").grid(row=0, column=0, padx=10, pady=10)
    dst_ip_entry = tk.Entry(layer_3_window, width=30)
    dst_ip_entry.grid(row=0, column=1, padx=10, pady=10)

    tk.Label(layer_3_window, text="Protocol:").grid(row=1, column=0, padx=10, pady=10)
    protocol_combobox = ttk.Combobox(layer_3_window, values=["ICMP", "TCP", "UDP"], state="readonly")
    protocol_combobox.set("ICMP")
    protocol_combobox.grid(row=1, column=1, padx=10, pady=10)

    tk.Label(layer_3_window, text="Source Port (TCP/UDP):").grid(row=2, column=0, padx=10, pady=10)
    src_port_entry = tk.Entry(layer_3_window, width=10)
    src_port_entry.insert(0, "12345")
    src_port_entry.grid(row=2, column=1, padx=10, pady=10)

    tk.Label(layer_3_window, text="Destination Port (TCP/UDP):").grid(row=3, column=0, padx=10, pady=10)
    dst_port_entry = tk.Entry(layer_3_window, width=10)
    dst_port_entry.grid(row=3, column=1, padx=10, pady=10)

    tk.Label(layer_3_window, text="Payload (optional):").grid(row=4, column=0, padx=10, pady=10)
    payload_entry = tk.Entry(layer_3_window, width=30)
    payload_entry.grid(row=4, column=1, padx=10, pady=10)

    tk.Label(layer_3_window, text="Number of Packets:").grid(row=5, column=0, padx=10, pady=10)
    packet_count_entry = tk.Entry(layer_3_window, width=10)
    packet_count_entry.insert(0, "1")
    packet_count_entry.grid(row=5, column=1, padx=10, pady=10)

    send_button = tk.Button(layer_3_window, text="Send", command=send)
    send_button.grid(row=6, column=0, columnspan=2, pady=20)

def main():
    root = tk.Tk()
    root.title("Packet Crafting Tool")

    tk.Label(root, text="Select Layer:").grid(row=0, column=0, padx=10, pady=10)

    layer_combobox = ttk.Combobox(root, values=["Layer 2", "Layer 3", "Layer 4"], state="readonly")
    layer_combobox.set("Layer 2")
    layer_combobox.grid(row=0, column=1, padx=10, pady=10)

    def proceed():
        layer = layer_combobox.get()
        if layer == "Layer 2":
            craft_layer_2()
        elif layer == "Layer 3":
            craft_layer_3()
        elif layer == "Layer 4":
            craft_layer_4()  # Call the new function

    proceed_button = tk.Button(root, text="Proceed", command=proceed)
    proceed_button.grid(row=1, column=0, columnspan=2, pady=20)

    root.mainloop()

def craft_layer_4():
    def send():
        iface = conf.iface  # Default network interface
        src_ip = get_if_addr(iface)  # Get system's IP address
        dst_ip = dst_ip_entry.get()
        protocol = protocol_combobox.get().upper()
        src_port = int(src_port_entry.get())
        dst_port = int(dst_port_entry.get())
        payload = payload_entry.get()
        count = int(packet_count_entry.get())

        if not dst_ip:
            messagebox.showerror("Error", "Destination IP address is required!")
            return

        if protocol == "TCP":
            packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)
            tcp_flags = tcp_flags_entry.get()
            if tcp_flags:
                packet[TCP].flags = tcp_flags
        elif protocol == "UDP":
            packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port)
        else:
            messagebox.showerror("Error", "Invalid protocol selected!")
            return

        if payload:
            packet = packet / Raw(load=payload)

        try:
            for _ in range(count):
                sendp(packet)
            messagebox.showinfo("Success", "Packet(s) sent successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send packet: {e}")

    layer_4_window = tk.Toplevel()
    layer_4_window.title("Craft Layer 4 Packet")

    tk.Label(layer_4_window, text="Destination IP Address:").grid(row=0, column=0, padx=10, pady=10)
    dst_ip_entry = tk.Entry(layer_4_window, width=30)
    dst_ip_entry.grid(row=0, column=1, padx=10, pady=10)

    tk.Label(layer_4_window, text="Protocol (TCP/UDP):").grid(row=1, column=0, padx=10, pady=10)
    protocol_combobox = ttk.Combobox(layer_4_window, values=["TCP", "UDP"], state="readonly")
    protocol_combobox.set("TCP")
    protocol_combobox.grid(row=1, column=1, padx=10, pady=10)

    tk.Label(layer_4_window, text="Source Port:").grid(row=2, column=0, padx=10, pady=10)
    src_port_entry = tk.Entry(layer_4_window, width=10)
    src_port_entry.insert(0, "12345")
    src_port_entry.grid(row=2, column=1, padx=10, pady=10)

    tk.Label(layer_4_window, text="Destination Port:").grid(row=3, column=0, padx=10, pady=10)
    dst_port_entry = tk.Entry(layer_4_window, width=10)
    dst_port_entry.grid(row=3, column=1, padx=10, pady=10)

    tk.Label(layer_4_window, text="TCP Flags (e.g., S for SYN):").grid(row=4, column=0, padx=10, pady=10)
    tcp_flags_entry = tk.Entry(layer_4_window, width=10)
    tcp_flags_entry.grid(row=4, column=1, padx=10, pady=10)

    tk.Label(layer_4_window, text="Payload (optional):").grid(row=5, column=0, padx=10, pady=10)
    payload_entry = tk.Entry(layer_4_window, width=30)
    payload_entry.grid(row=5, column=1, padx=10, pady=10)

    tk.Label(layer_4_window, text="Number of Packets:").grid(row=6, column=0, padx=10, pady=10)
    packet_count_entry = tk.Entry(layer_4_window, width=10)
    packet_count_entry.insert(0, "1")
    packet_count_entry.grid(row=6, column=1, padx=10, pady=10)

    send_button = tk.Button(layer_4_window, text="Send", command=send)
    send_button.grid(row=7, column=0, columnspan=2, pady=20)


if __name__ == "__main__":
    main()
