
# Wireshark Lite - Packet Sniffer

This is a Python-based packet sniffer application that captures network packets and displays them in a graphical user interface (GUI) built using Tkinter. It is inspired by the popular tool Wireshark, with basic functionalities for packet sniffing, filtering, and exporting captured data.

## Features

- **Capture Packets**: Capture and display network packets in real-time.
- **Protocol Filtering**: Filter captured packets by protocol (TCP, UDP, ICMP).
- **Pause/Resume**: Pause and resume packet sniffing.
- **Export to CSV**: Export captured packet data to a CSV file.
- **Save Packet Dump**: Save the raw packet data to a text file.
- **Search**: Search through the packet details in real-time.
- **GUI**: User-friendly interface built using Tkinter.

## Requirements

Before running the application, make sure you have the following Python packages installed:

- `scapy`: For capturing and processing network packets.
- `tkinter`: For building the graphical user interface.

To install the required packages, create a virtual environment (optional but recommended) and install the dependencies using `requirements.txt`.

### Install Dependencies

```bash
pip install -r requirements.txt
```

## Project Structure

```
packet_sniffer/
├── main.py               # Entry point for the application
├── packet_processing.py  # Logic for packet sniffing and processing
├── ui_elements.py        # UI components and layouts
├── utils.py              # Helper functions (e.g., search, export)
└── requirements.txt      # Python dependencies (e.g., scapy, tkinter)
```

### File Descriptions

- `main.py`: This file contains the main entry point for the application. It initializes the window and loads the UI components. It also starts and stops the sniffing process.
- `packet_processing.py`: This file contains the packet sniffing logic. It captures packets, processes them, and stores them for later display or export.
- `ui_elements.py`: This file defines the user interface components, such as buttons, labels, treeviews, and text fields.
- `utils.py`: Contains helper functions for exporting packet data to CSV, saving packet dumps, and handling search operations.

## Usage

1. Clone this repository to your local machine.

```bash
git clone https://github.com/yourusername/wireshark-lite.git
cd wireshark-lite
```

2. Install the required dependencies from the `requirements.txt` file.

```bash
pip install -r requirements.txt
```

3. Run the application using:

```bash
python main.py
```

4. The application window will appear. You can start sniffing network packets, apply filters (TCP, UDP, ICMP), and pause/resume packet capture.

5. Once packets are captured, you can:
   - Search for specific information.
   - Export the captured data to a CSV file.
   - Save raw packet dumps to a text file.

## Screenshots

(Optional) Add screenshots or GIFs of the application here.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- Scapy: [https://scapy.readthedocs.io/en/latest/](https://scapy.readthedocs.io/en/latest/)
- Tkinter: [https://docs.python.org/3/library/tkinter.html](https://docs.python.org/3/library/tkinter.html)
