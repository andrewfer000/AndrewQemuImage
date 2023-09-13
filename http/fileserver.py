import http.server
import socketserver

HOST = "127.0.0.1"  # Change this to the desired IP address or hostname
PORT = 8576  # Change this to the desired port number

Handler = http.server.SimpleHTTPRequestHandler

httpd = socketserver.TCPServer((HOST, PORT), Handler)

print(f"Serving files on {HOST}:{PORT}.")
try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print("\nServer terminated by user.")
    httpd.server_close()

