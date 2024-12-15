# Packet Crafting Tool

## Overview

This tool is a graphical user interface (GUI)-based packet crafting application built using Python's `tkinter` module and the `scapy` library. It allows users to craft and send network packets at various layers (Layer 2, Layer 3, and Layer 4) with customizable options such as payload, protocols, ports, and more.

## Features

1. Layer 2 Packet Crafting**

   - Specify destination MAC address.
   - Add optional payload data.
   - Define the number of packets to send.

2. Layer 3 Packet Crafting**

   - Specify destination IP address.
   - Choose from ICMP, TCP, or UDP protocols.
   - Add optional payload data.
   - Configure source and destination ports for TCP/UDP packets.
   - Define the number of packets to send.

3. Layer 4 Packet Crafting**

   - Specify source and destination IP addresses and ports.
   - Choose from TCP or UDP protocols.
   - Add optional TCP flags (e.g., SYN).
   - Add optional payload data.
   - Define the number of packets to send.

## Requirements

- Python 3.x
- `scapy` library
- `tkinter` (bundled with Python by default on most platforms)

## Installation

1. Install Python 3.x from the [official Python website](https://www.python.org/).
2. Install the `scapy` library:
   ```bash
   pip install scapy
   ```
3. Save the script to a file, e.g., `packet_crafting_tool.py`.

## Usage

1. Run the script:
   ```bash
   python packet_crafting_tool.py
   ```
2. Select the layer you want to craft packets for (Layer 2, Layer 3, or Layer 4).
3. Fill in the required details in the respective window.
4. Click the "Send" button to craft and send the packets.

## GUI Components

- Main Window:**

  - Dropdown to select the network layer.
  - Button to proceed to the selected layer's crafting window.

- Layer 2 Crafting Window:**

  - Input fields for destination MAC address, payload, and packet count.
  - "Send" button to transmit the packets.

- **Layer 3 Crafting Window:**

  - Input fields for destination IP address, protocol, source/destination ports, payload, and packet count.
  - Dropdown to select ICMP, TCP, or UDP.
  - "Send" button to transmit the packets.

- Layer 4 Crafting Window:**

  - Input fields for source/destination IP addresses, source/destination ports, TCP flags, payload, and packet count.
  - Dropdown to select TCP or UDP.
  - "Send" button to transmit the packets.

## Notes

- Ensure you have the required permissions to send crafted packets. You might need to run the script with administrative/root privileges.
- Misuse of this tool to disrupt networks or unauthorized systems may be illegal. Use responsibly.

## License

This tool is provided "as is" for educational and research purposes. The author is not responsible for any misuse or damage caused by this software.

## Contributions

Contributions, bug reports, and feature requests are welcome! Please create an issue or a pull request in the GitHub repository.

## Disclaimer

This tool is intended for ethical purposes only, such as learning about networking, testing, or research. Always ensure you have proper authorization before using it on a network.
