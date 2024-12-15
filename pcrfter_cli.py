from scapy.all import * 
def packet_crafting():
    layer = input("For which layer you want to craft packet? Type 2 for Ether, 3 for IP, 4 for TCP, and 7 for Application: ")
    if layer == '2':
        def layer_2():
            iface = conf.iface 
            src_mac = get_if_hwaddr(iface) 
            print(f"Using source MAC address: {src_mac}")
            dst_mac = input("Enter the destination MAC address: ")
            ether = Ether(src=src_mac, dst = dst_mac)
            return ether
        packet = layer_2()
        custom_payload = input("Do you want to add any payload with the packet? Type 'y' for yes and 'n' for no: ")
        if custom_payload == 'y':
            payld = input("Enter payload as a string; ")
            packet = packet / Raw(load=payld)
        total_packets = int(input("How many packets to send?: "))
        for i in range(0,total_packets):
            sendp(packet)
    elif layer == '3':
        def layer_3():
            dest = input("Enter the destination/Target IP: ")
            ip = IP(dst=dest)  # Source IP can be default or specified later
            return ip

        packet = layer_3()

        # Ask for custom payload first
        custom_payload = input("Do you want to add any custom payload? Type 'y' for yes and 'n' for no: ").lower()
        if custom_payload == 'y':
            payld = input("Enter the payload: ")
            packet = packet / Raw(load=payld)

        # Ask for protocol after payload decision
        protocol = input("Enter the protocol (e.g., ICMP, TCP, UDP): ").upper()
        if protocol == "ICMP":
            packet = packet / ICMP()
            total_packets = int(input("How many packets to send?: "))
            for i in range(0,total_packets):
                sendp(packet)
        elif protocol == "TCP":
            src_port = int(input("Enter source port: "))
            dst_port = int(input("Enter destination port: "))
            packet = packet / TCP(sport=src_port, dport=dst_port)
            total_packets = int(input("How many packets to send?: "))
            for i in range(0,total_packets):
                sendp(packet)
        elif protocol == "UDP":
            src_port = int(input("Enter source port: "))
            dst_port = int(input("Enter destination port: "))
            packet = packet / UDP(sport=src_port, dport=dst_port)
            total_packets = int(input("How many packets to send?: "))
            for i in range(0,total_packets):
                sendp(packet)
        else:
            print("Invalid protocol. Please enter ICMP, TCP, or UDP.") 
    elif layer == '4':
        def layer_4_packet():
    # Get system's IP address for the source
            iface = conf.iface  # Default network interface
            src_ip = get_if_addr(iface)  # Get IP address of the active interface
            print(f"Using source IP address: {src_ip}")

    # Get the destination IP address
            dst_ip = input("Enter the destination IP address: ")

    # Ask the user to choose the Layer 4 protocol
            protocol = input("Choose the Layer 4 protocol (TCP/UDP): ").upper()

    # Common options
            src_port = int(input("Enter source port (default 12345): ") or 12345)
            dst_port = int(input("Enter destination port: "))

            if protocol == "TCP":
        # Create a TCP packet
                tcp_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)

        # Ask if the user wants to set additional flags
                flags = input("Enter TCP flags (e.g., S for SYN, A for ACK, F for FIN) or press Enter for default (S): ") or "S"
                tcp_packet[TCP].flags = flags

        # Ask for optional payload
                add_payload = input("Do you want to add a payload? (y/n): ").lower()
                if add_payload == 'y':
                    payload = input("Enter the payload (as a string): ")
                    tcp_packet = tcp_packet / Raw(load=payload)

                return tcp_packet
        packet = layer_4_packet()
        sendp(packet)

    elif protocol == "UDP":
        # Create a UDP packet
        udp_packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port)

        # Ask for optional payload
        add_payload = input("Do you want to add a payload? (y/n): ").lower()
        if add_payload == 'y':
            payload = input("Enter the payload (as a string): ")
            udp_packet = udp_packet / Raw(load=payload)

        return udp_packet
    else:
        print("Currently, only Layer 2 (Ethernet) is supported in this script. Extend for other layers as needed.")
    
packet_crafting()
