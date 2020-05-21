import http.server
import socketserver
import os

PORT = 8000
DIRECTORY = "web"

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        """Serve a GET request."""
        path = self.translate_path(self.path)
        print(path)
        if os.path.isfile(path) and os.access(path, os.X_OK) :
            print('Executing',path)
            os.system(path)
        else :
            print('Not executable')
        f = self.send_head()
        if f:
            self.copyfile(f, self.wfile)
            f.close()
            
#Handler = http.server.SimpleHTTPRequestHandler

httpd = socketserver.TCPServer(("", PORT), Handler)
print("serving at port", PORT)
httpd.serve_forever()
