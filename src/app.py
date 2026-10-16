"""
Vulnerable Web Application - Layer 2 Hardware MAC Filtering
Author: Jaser Halabi
Purpose: Demonstrates the security risks of relying solely on Layer 2 MAC addresses 
         for application access control and identity validation.
"""

from flask import Flask, request
from getmac import get_mac_address

app = Flask(__name__)

# Static list of authorized hardware MAC addresses
ALLOWED_DEVICES = [
    "00:0C:29:18:ED:4F"
]


@app.route("/")
def security_check():
    client_ip = request.remote_addr
    client_mac = get_mac_address(ip=client_ip)

    if client_mac is not None:
        client_mac = client_mac.upper().replace("-", ":")

    print(f"Incoming Request -> IP: {client_ip} | MAC: {client_mac}")

    if client_mac in ALLOWED_DEVICES:
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Access Granted</title>
        </head>
        <body style="background-color: #d4edda; font-family: sans-serif; text-align: center; padding-top: 50px;">
            <h1 style="color: #155724;">✅ SUCCESS: ACCESS GRANTED</h1>
            <p>Welcome back, Authorized User.</p>
            <p>Identity confirmed via Hardware MAC.</p>
        </body>
        </html>
        """
    else:
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Access Denied</title>
        </head>
        <body style="background-color: #f8d7da; font-family: sans-serif; text-align: center; padding-top: 50px;">
            <h1 style="color: #721c24;">❌ ACCESS DENIED</h1>
            <p><strong>Identity Theft Detected!</strong></p>
            <p>MAC: <code>{client_mac if client_mac else 'Unknown'}</code> is not authorized.</p>
            <p>Security protocols engaged.</p>
        </body>
        </html>
        """, 403


if __name__ == "__main__":
    print("[*] Starting MAC-filtered security server on http://0.0.0.0:80")
    print(f"[*] Whitelisted MAC addresses: {ALLOWED_DEVICES}")
    app.run(host="0.0.0.0", port=80, debug=False)
