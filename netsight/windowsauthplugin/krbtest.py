# This is a small simple Win32 standalone test server to test that the AD single sign on from the client is working

import sspi, sspicon
import SimpleHTTPServer
import base64
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

class TestServer(BaseHTTPRequestHandler):
    
    def do_GET(self):
        authz = self.headers.get('Authorization', '')
        if authz.startswith('Negotiate '):
            authz = authz[len('Negotiate '):]
            print authz
            data = authz.decode('base64')
            sa = sspi.ServerAuth('Negotiate')
            sa.reset()
            err, sec_buffer = sa.authorize(data)

            if err == 0:
                username = sa.ctxt.QueryContextAttributes(
                    sspicon.SECPKG_ATTR_NAMES)
		               
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write('<HTML><body>Authenticated! Username: %s</body></HTML>' % username)
                return
            else:
                print "Error: ", err


        self.send_response(401)
        self.send_header('Content-type', 'text/html')
	self.send_header('WWW-Authenticate', 'Negotiate')
        self.end_headers()
        self.wfile.write('<HTML><body>Must authenticate</body></HTML>')
       
srvr = HTTPServer(('', 80), TestServer)
srvr.serve_forever()
