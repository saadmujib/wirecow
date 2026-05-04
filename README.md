# Network Traffic Monitor

This is a simple web-based real time network traffic monitor built for my Computer Networks project. It uses Python to capture real-time packets and displays them on a web interface.

## Tech Stack
* **Backend:** Python (Flask, Scapy)
* **Frontend:** HTML, CSS, JS

## Features
* Live packet capturing (TCP, UDP, ICMP)
* Packet filtering by IP, Port, and Protocol
* Real-time statistics (total packets, average size)
* Auto-updating logs and data table

## How to Run
1. Make sure Python is installed.
2. Install the required libraries:
   `pip install flask scapy`
3. Run the app (you might need admin/sudo rights for packet sniffing):
   `sudo python app.py`
4. Open your browser and go to `http://127.0.0.1:5000`

5. Also keep the `index.html` in `/templates`, so the hierarchy looks like:

```text
MainFolder/
├── app.py
└── templates/
    └── index.html
