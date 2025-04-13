"""
local_wifi_file_transfer.py

A Python script (with tkinter GUI) that:
1. Lets the user select multiple files to share at once.
2. Hosts a simple HTTP server that shows a link for each file at "/" so clients
   can choose which file(s) to download.
3. Uses a rolling-average approach to display speed & ETA for each client's
   file download. If multiple files are downloaded concurrently (by one or more
   clients), each has its own progress bar.
4. If a transfer fails, that specific download entry is marked as failed.

Usage:
1. Ensure all devices (server & clients) are on the same Wi-Fi/hotspot network.
2. Run this script: python multi_file_http_server.py
3. In the GUI:
   - Click "Choose Files" to select multiple files to share.
   - Click "Start Server."
   - The GUI will show "Listening on http://<IP>:<port>" when running.
4. On a client device:
   - Open a browser to http://<server_ip>:<port> 
   - You will see links for each file you shared. Click the file you want to download.
   - A new progress bar appears in the server GUI for each (client_ip, file_name).
"""

import os
import socket
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox
import tkinter.ttk as ttk
import queue

import http.server
import socketserver
import re
import subprocess
from collections import deque
from urllib.parse import unquote


# --------------------------------------------------------------------
# 1) Utility: ARP Table (Optional for MAC Lookup)
# --------------------------------------------------------------------

def get_arp_table():
    """
    Parse the local ARP table (via `arp -a`) to get IP->MAC mappings.
    Returns a dict: { '192.168.x.x': '00-11-22-33-44-55', ... }
    """
    mapping = {}
    try:
        cmd = ["arp", "-a"]
        output = subprocess.check_output(cmd, shell=True, text=True)
        for line in output.splitlines():
            match = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]+)\s+(\w+)", line.strip())
            if match:
                ip = match.group(1).strip()
                mac = match.group(2).strip().lower().replace("-", ":")
                mapping[ip] = mac
    except:
        pass
    return mapping


# --------------------------------------------------------------------
# 2) HTTP Handler (Multi-File)
# --------------------------------------------------------------------

class MultiFileHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """
    A custom HTTP handler that:
    - On GET /, shows an index page with links to all shared files.
    - On GET /<filename>, serves that file (if it is in the shared set).
    - Tracks progress of each file transfer with a rolling average for speed & ETA.
    - Notifies the GUI of events (NEW_CLIENT, PROGRESS, DONE, FAIL) with keys:
        (client_ip, client_port, file_name)
    """

    # shared_files: dict[filename -> full_path]
    # Example: { 'example.txt': 'C:/path/to/example.txt', 'report.pdf': 'C:/stuff/report.pdf' }
    shared_files = {}

    # Each file’s size: dict[filename -> int]
    file_sizes = {}

    # Rolling window in seconds for average speed
    ROLLING_WINDOW = 3.0

    # A queue to notify the GUI
    gui_queue = None

    # Download tracking: key=(client_ip, client_port, filename), value={
    #    'bytes_sent': ...
    #    'percent': ...
    #    'speed_mbps': ...
    #    'eta_seconds': ...
    # }
    download_map = {}

    def do_GET(self):
        client_ip, client_port = self.client_address
        mac_addr = None

        # Try ARP lookups for MAC
        arp_map = get_arp_table()
        if client_ip in arp_map:
            mac_addr = arp_map[client_ip]

        # If path is "/", display index with links for each shared file
        if self.path == "/":
            self._handle_index()
            return

        # Otherwise, check if the user requested one of the shared files
        requested_file = unquote(self.path.lstrip("/"))  # remove leading slash
        if requested_file in MultiFileHTTPRequestHandler.shared_files:
            full_path = MultiFileHTTPRequestHandler.shared_files[requested_file]
            self._handle_file_download(client_ip, client_port, mac_addr, requested_file, full_path)
        else:
            self.send_error(404, "File not found.")

    def _handle_index(self):
        """Serve an index page listing all shared files."""
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()

        if not MultiFileHTTPRequestHandler.shared_files:
            # No files
            html = """
            <html>
              <head><title>No Files</title></head>
              <body>
                <h3>No files are currently shared on this server.</h3>
              </body>
            </html>
            """
        else:
            # Show a link for each file
            links = ""
            for fname in MultiFileHTTPRequestHandler.shared_files:
                links += f'<li><a href="/{fname}">{fname}</a></li>\n'
            html = f"""
            <html>
              <head><title>Files Available</title></head>
              <body>
                <h3>Choose a file to download:</h3>
                <ul>
                  {links}
                </ul>
              </body>
            </html>
            """

        self.wfile.write(html.encode("utf-8"))

    def _handle_file_download(self, ip, port, mac_addr, file_name, full_path):
        """Serve the specified file_name from full_path, with rolling avg for speed."""
        if not os.path.exists(full_path):
            self.send_error(404, "File not found on disk.")
            return

        file_size = MultiFileHTTPRequestHandler.file_sizes.get(file_name, 0)
        key = (ip, port, file_name)

        # Initialize the tracking map
        MultiFileHTTPRequestHandler.download_map[key] = {
            "ip": ip,
            "port": port,
            "filename": file_name,
            "mac": mac_addr,
            "bytes_sent": 0,
            "percent": 0.0,
            "speed_mbps": 0.0,
            "eta_seconds": 0,
            "file_size": file_size,
        }

        # Notify GUI about new download
        self._gui_event("NEW_CLIENT", {
            "ip": ip,
            "port": port,
            "filename": file_name,
            "mac": mac_addr,
            "file_size": file_size
        })

        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{file_name}"')
            self.end_headers()

            bytes_sent = 0
            rolling_data = deque()
            chunk_size = 64 * 1024

            with open(full_path, "rb") as f:
                while True:
                    chunk_start = time.time()
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    self.wfile.write(chunk)
                    chunk_len = len(chunk)
                    bytes_sent += chunk_len

                    # Insert the chunk info in rolling_data
                    rolling_data.append((chunk_start, chunk_len))

                    # Remove old entries
                    cutoff = chunk_start - MultiFileHTTPRequestHandler.ROLLING_WINDOW
                    while rolling_data and rolling_data[0][0] < cutoff:
                        rolling_data.popleft()

                    # Sum bytes in the rolling window
                    if rolling_data:
                        time_span = rolling_data[-1][0] - rolling_data[0][0]
                        total_bytes_in_window = sum(x[1] for x in rolling_data)
                        speed_bps = (total_bytes_in_window / time_span) if time_span > 0 else 0
                    else:
                        speed_bps = 0

                    speed_mbps = speed_bps * 8 / 1_000_000

                    # Calculate progress
                    if file_size > 0:
                        percent = (bytes_sent / file_size) * 100
                    else:
                        percent = 100

                    # ETA
                    remaining = file_size - bytes_sent
                    eta_seconds = int(remaining / speed_bps) if speed_bps > 0 else 0

                    # Update in the dictionary
                    MultiFileHTTPRequestHandler.download_map[key]["bytes_sent"] = bytes_sent
                    MultiFileHTTPRequestHandler.download_map[key]["percent"] = percent
                    MultiFileHTTPRequestHandler.download_map[key]["speed_mbps"] = speed_mbps
                    MultiFileHTTPRequestHandler.download_map[key]["eta_seconds"] = eta_seconds

                    # Notify GUI
                    self._gui_event("PROGRESS", {
                        "ip": ip,
                        "port": port,
                        "filename": file_name,
                        "percent": percent,
                        "bytes_sent": bytes_sent,
                        "file_size": file_size,
                        "speed_mbps": speed_mbps,
                        "eta_seconds": eta_seconds
                    })

            # Done
            self._gui_event("DONE", {"ip": ip, "port": port, "filename": file_name})

        except Exception as e:
            self._gui_event("FAIL", {
                "ip": ip,
                "port": port,
                "filename": file_name,
                "error": str(e)
            })

    def _gui_event(self, event_type, data):
        """Push an event onto the GUI queue for the main thread to handle."""
        if MultiFileHTTPRequestHandler.gui_queue:
            MultiFileHTTPRequestHandler.gui_queue.put((event_type, data))


# --------------------------------------------------------------------
# 3) Threaded HTTP Server
# --------------------------------------------------------------------

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Handle requests in a separate thread."""


# --------------------------------------------------------------------
# 4) The GUI
# --------------------------------------------------------------------

class MultiFileHTTPGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Multi-File HTTP Transfer with Rolling ETA")

        # Server
        self.server_port = 50000
        self.httpd = None
        self.server_thread = None
        self.server_running = False

        # Store (filename -> path)
        self.shared_files = {}
        # Store file sizes
        self.file_sizes = {}

        # For thread-safe UI updates from HTTP handler
        self.gui_queue = queue.Queue()

        # Keep track of each download's UI elements
        # Key = (ip, port, filename)
        # Value = { 'frame':..., 'progress_var':..., 'stats_var':..., ... }
        self.client_widgets = {}

        # Build UI
        self._build_ui()

        # Poll the queue every 100ms
        self._poll_gui_queue()

        # Styles for normal & "failure" progress bars
        self.style = ttk.Style(self)
        self.style.theme_use("default")
        self.style.configure("Failed.Horizontal.TProgressbar", foreground="red", background="red")

    def _build_ui(self):
        # Left frame for instructions + file server
        left_frame = tk.Frame(self)
        left_frame.pack(side="left", fill="y", padx=5, pady=5)

        # Instructions
        reminder_frame = tk.LabelFrame(left_frame, text="Reminder", padx=5, pady=5)
        reminder_frame.pack(fill="x", expand=False, pady=5)
        tk.Label(
            reminder_frame,
            text=("Make sure this PC and clients\n"
                  "are on the same Wi-Fi/hotspot.\n"
                  "Start the server and open the link\n"
                  "in a browser on client devices."),
            fg="blue"
        ).pack(anchor="w")

        # File/Server Frame
        server_frame = tk.LabelFrame(left_frame, text="File Server", padx=5, pady=5)
        server_frame.pack(fill="x", expand=False, pady=5)

        choose_btn = tk.Button(server_frame, text="Choose Files", command=self.choose_files)
        choose_btn.grid(row=0, column=0, padx=5, pady=2, sticky="w")

        self.file_label = tk.Label(server_frame, text="No files selected.", fg="blue")
        self.file_label.grid(row=0, column=1, sticky="w", padx=5)

        tk.Label(server_frame, text="Server Port:").grid(row=1, column=0, sticky="e", padx=5)
        self.port_entry = tk.Entry(server_frame, width=6)
        self.port_entry.insert(0, str(self.server_port))
        self.port_entry.grid(row=1, column=1, sticky="w")

        start_btn = tk.Button(server_frame, text="Start Server", command=self.start_server)
        start_btn.grid(row=2, column=0, padx=5, pady=5)
        stop_btn = tk.Button(server_frame, text="Stop Server", command=self.stop_server)
        stop_btn.grid(row=2, column=1, padx=5, pady=5)

        self.listening_label = tk.StringVar(value="Not listening.")
        tk.Label(server_frame, textvariable=self.listening_label, fg="red").grid(
            row=3, column=0, columnspan=2, sticky="w"
        )

        # Status box
        status_frame = tk.LabelFrame(left_frame, text="Status Log", padx=5, pady=5)
        status_frame.pack(fill="both", expand=True, pady=5)
        self.status_text = tk.Text(status_frame, height=10, wrap="word")
        self.status_text.pack(fill="both", expand=True)

        # Right frame for connected downloads
        right_frame = tk.LabelFrame(self, text="Connected Downloads", padx=5, pady=5)
        right_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        self.clients_container = tk.Frame(right_frame)
        self.clients_container.pack(fill="both", expand=True)

    def choose_files(self):
        """Open a file dialog to select multiple files."""
        file_paths = filedialog.askopenfilenames()
        if not file_paths:
            return

        # Reset local dict
        self.shared_files.clear()
        self.file_sizes.clear()

        # Populate
        for path in file_paths:
            fname = os.path.basename(path)
            self.shared_files[fname] = path
            self.file_sizes[fname] = os.path.getsize(path)

        if self.shared_files:
            # Show short summary in label
            summary = ", ".join(list(self.shared_files.keys()))
            self.file_label.config(text=summary[:100] + ("..." if len(summary) > 100 else ""))
        else:
            self.file_label.config(text="No files selected.")

    def start_server(self):
        if self.server_running:
            messagebox.showinfo("Info", "Server is already running.")
            return

        if not self.shared_files:
            messagebox.showerror("Error", "Please select at least one file to share.")
            return

        # Validate port
        try:
            self.server_port = int(self.port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid port number.")
            return

        # Pass these to the handler
        MultiFileHTTPRequestHandler.shared_files = dict(self.shared_files)
        MultiFileHTTPRequestHandler.file_sizes = dict(self.file_sizes)
        MultiFileHTTPRequestHandler.gui_queue = self.gui_queue
        MultiFileHTTPRequestHandler.download_map = {}

        # Start server
        try:
            self.httpd = ThreadedHTTPServer(("0.0.0.0", self.server_port), MultiFileHTTPRequestHandler)
            self.server_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            self.server_thread.start()
            self.server_running = True

            # Show local IP
            ip_list = self._get_local_ip_addresses()
            if ip_list:
                ip_str = ip_list[0]
                self.listening_label.set(f"Listening on http://{ip_str}:{self.server_port}")
                self._log(f"Server started at http://{ip_str}:{self.server_port}")
            else:
                self.listening_label.set(f"Listening on port {self.server_port}")
                self._log(f"Server started on 0.0.0.0:{self.server_port}")

        except Exception as e:
            self._log(f"Error starting server: {e}")
            messagebox.showerror("Error", f"Could not start server: {e}")

    def stop_server(self):
        if not self.server_running:
            self._log("Server not running.")
            return
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.server_running = False
            self.listening_label.set("Not listening.")
            self._log("Server stopped.")
        except Exception as e:
            self._log(f"Error stopping server: {e}")

    def _log(self, message):
        self.status_text.insert(tk.END, f"{message}\n")
        self.status_text.see(tk.END)
        print(message)

    def _get_local_ip_addresses(self):
        """Return a list of IPv4 addresses on this machine."""
        ips = []
        hostname = socket.gethostname()
        try:
            infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
            for entry in infos:
                ip = entry[4][0]
                if ip not in ips:
                    ips.append(ip)
        except:
            pass
        return ips

    # ------------------------------------------------------------
    # Periodically poll the GUI queue for events from the handler
    # ------------------------------------------------------------
    def _poll_gui_queue(self):
        try:
            while True:
                event_type, data = self.gui_queue.get_nowait()

                if event_type == "NEW_CLIENT":
                    self._new_download(data)

                elif event_type == "PROGRESS":
                    self._progress_download(data)

                elif event_type == "DONE":
                    self._finish_download(data)

                elif event_type == "FAIL":
                    self._fail_download(data)

        except queue.Empty:
            pass

        self.after(100, self._poll_gui_queue)

    # ------------------------------------------------------------
    # Download UI Updates
    # ------------------------------------------------------------

    def _new_download(self, data):
        """
        data = {
          "ip": ..., "port": ..., "filename": ...,
          "mac": ..., "file_size": ...
        }
        Create a new row for (ip, port, filename).
        """
        ip = data["ip"]
        port = data["port"]
        filename = data["filename"]
        mac = data.get("mac", "")
        file_size = data["file_size"]

        key = (ip, port, filename)

        if key in self.client_widgets:
            # Reset
            w = self.client_widgets[key]
            w["progress_var"].set(0)
            w["pbar"].configure(style="Horizontal.TProgressbar")
            w["stats_var"].set("")
        else:
            frame = tk.Frame(self.clients_container, bd=1, relief="solid", padx=5, pady=5)
            frame.pack(fill="x", padx=2, pady=2)

            title_text = f"{ip}:{port} - {filename}"
            if mac:
                title_text += f" [{mac}]"

            title_label = tk.Label(frame, text=title_text)
            title_label.pack(anchor="w")

            pvar = tk.DoubleVar(value=0)
            pbar = ttk.Progressbar(frame, orient="horizontal", length=200,
                                   mode="determinate", variable=pvar)
            pbar.pack(anchor="w", fill="x", expand=True)
            pbar["maximum"] = 100

            stats_var = tk.StringVar(value="")
            stats_label = tk.Label(frame, textvariable=stats_var, fg="gray")
            stats_label.pack(anchor="w")

            self.client_widgets[key] = {
                "frame": frame,
                "progress_var": pvar,
                "pbar": pbar,
                "stats_var": stats_var
            }

        self._log(f"NEW download: {ip}:{port} => {filename} (size={file_size} bytes)")

    def _progress_download(self, data):
        """
        data = {
          'ip':..., 'port':..., 'filename':...,
          'percent':..., 'bytes_sent':..., 'file_size':...,
          'speed_mbps':..., 'eta_seconds':...
        }
        """
        ip = data["ip"]
        port = data["port"]
        filename = data["filename"]
        key = (ip, port, filename)

        w = self.client_widgets.get(key)
        if not w:
            return

        percent = data["percent"]
        w["progress_var"].set(percent)

        bytes_sent = data["bytes_sent"]
        file_size = data["file_size"]
        speed_mbps = data["speed_mbps"]
        eta_seconds = data["eta_seconds"]

        # Format speed & ETA
        speed_str = f"{speed_mbps:.1f} Mbps"

        # Convert ETA seconds to H:MM:SS
        if eta_seconds < 60:
            eta_str = f"{eta_seconds}s"
        elif eta_seconds < 3600:
            m, s = divmod(eta_seconds, 60)
            eta_str = f"{m}m {s}s"
        else:
            h, rem = divmod(eta_seconds, 3600)
            m, s = divmod(rem, 60)
            eta_str = f"{h}h {m}m {s}s"

        # Format "transferred / total"
        def fmt_mb(x):
            return f"{x/1_048_576:.2f} MB"
        transferred_str = fmt_mb(bytes_sent)
        total_str = fmt_mb(file_size)

        stats = f"Speed: {speed_str}, ETA: {eta_str}, {transferred_str} / {total_str}"
        w["stats_var"].set(stats)

    def _finish_download(self, data):
        """
        data = { 'ip':..., 'port':..., 'filename':... }
        """
        ip = data["ip"]
        port = data["port"]
        filename = data["filename"]
        key = (ip, port, filename)

        w = self.client_widgets.get(key)
        if w:
            w["progress_var"].set(100)
            w["stats_var"].set("Completed.")

        self._log(f"FINISHED download: {ip}:{port} => {filename}")

    def _fail_download(self, data):
        """
        data = { 'ip':..., 'port':..., 'filename':..., 'error':... }
        """
        ip = data["ip"]
        port = data["port"]
        filename = data["filename"]
        error = data.get("error", "")
        key = (ip, port, filename)

        w = self.client_widgets.get(key)
        if w:
            w["pbar"].configure(style="Failed.Horizontal.TProgressbar")
            w["progress_var"].set(0)
            w["stats_var"].set("Transfer failed.")

        self._log(f"FAILED download: {ip}:{port} => {filename} error={error}")


def main():
    app = MultiFileHTTPGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
