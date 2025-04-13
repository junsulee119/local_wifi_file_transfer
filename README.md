# Wi-Fi File Transfer (Multi-File HTTP Server)

This Python script provides a simple way to share multiple files over a local Wi-Fi/hotspot network. It uses a built-in HTTP server to list and serve the selected files. It also displays real-time speed, progress, and estimated time to complete (ETA) for each download on the server side.

## Features

- **Multiple File Selection**: Select one or more files to share.
- **Simple HTTP Server**: Files are accessible in a browser via a link on the same local network.
- **Real-Time Progress**: See each client’s download progress, speed (rolling average in Mbps), and ETA in the GUI.
- **Per-Download Tracking**: Each file and each client’s download progress is tracked independently.
- **Automatic Retry Handling**: If a transfer fails, that specific download is marked as failed (no crash or disruption to other transfers).

## How It Works

1. **Start the Server**  
   - Run the script on your machine.
   - Select the files you want to share.
   - Start the local HTTP server on the chosen port.
2. **Client Access**  
   - Any device on the same Wi-Fi/hotspot network can open a web browser and go to `http://<server_IP>:<port>`.
   - An index page lists all the shared files. Clicking on a file link initiates a download.
3. **Live Download Stats**  
   - In the server’s GUI, a new progress bar appears for each (client IP + file).
   - Shows percent downloaded, speed in Mbps, and ETA.

## Requirements

- **Python 3** (tested on Python 3.7+)
- **tkinter** for the GUI (often included by default in many Python installations)
- **No external libraries** are strictly required beyond the standard library.

## Installation & Usage

1. **Clone or Download**  
   ```bash
   git clone https://github.com/YourUsername/wifi-file-transfer.git
   cd wifi-file-transfer
2. **Run the Script**
    ```bash
    python wifi_file_transfer.py
3. **Select Files**
- Click the **Choose Files** button in the GUI and select any number of files.
4. **Start the Server**
- Enter a port number (default is `50000`) and click Start Server.
- You’ll see a message like “Listening on http://<server_IP>:<port>”.
5. **Download from Other Devices**
- On a different device (phone, laptop, etc.) connected to the same network, open a web browser and go to http://<server_IP>:<port>.
- Click any file link to start a download.
- The server’s GUI will show real-time progress bars for each active download.

## How to Stop the Server

- Click the **Stop Server** button in the GUI.
The script closes the HTTP server and stops accepting new connections, but it does not immediately terminate any in-progress downloads.

## Troubleshooting

- **Port Already in Use**
    - Change the port in the GUI to something else (e.g., `50001`) if you see errors about the port being unavailable.
- **Firewall Settings**
    - If clients can’t connect, make sure your firewall allows inbound connections on the specified port.
- **Different Network**
    - Ensure both the server and clients are connected to the same Wi-Fi/hotspot network.

## License

This project is licensed under the [GNU Affero General Public License v3.0](https://www.gnu.org/licenses/agpl-3.0.html).
