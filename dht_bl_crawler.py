###Running the crawler:
#Provide blacklist file with set of IP addresses
#Provide output folder to write
#Example python2.7 dht_bl_crawler.py blacklist_ips /n/output_folder/

import json
import os
import pickle
import glob
import socket
import binascii
from threading import Timer, Thread, Lock
from time import sleep
import time
import random
from bencode import bencode, bdecode
import bt_messages
import Queue
import datetime
import subprocess
import sys

skip_count=0
blacklist_file=sys.argv[1]
output_file=sys.argv[2]
ip_watcher={}

all_24=set()
f=open(blacklist_file,"r")
for line in f:
	ip=line.strip()
	ip_24=".".join(ip.split(".")[0:3])+".0"
	all_24.add(ip_24)
f.close()
print "Total blacklist 24",len(all_24)


lastreply_per_probe = {} #we store the timestamp of the last reply of probed IP:ports
ip_receiver={}
total_discovered_nodes=0
multiple_errors=0
one_time_error=0
total_nat=0
sleep_time=0
last_backup_time=0

conntrack_count=int(subprocess.Popen("cat /proc/sys/net/netfilter/nf_conntrack_count", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].strip())
fout = open(output_file+"/"+datetime.datetime.now().strftime("%Y_%m_%d_%H_%M") + ".out","w")
foutcounter = 0

writelock = Lock()

def writeOutput(line):
	global foutcounter
	global fout
	global writelock
	foutcounter += 1
	writelock.acquire()
	if foutcounter >= 3000000:
		fout.close()
		fout = open(output_file+"/"+datetime.datetime.now().strftime("%Y_%m_%d_%H_%M") + ".out","w")
		foutcounter = 0
		fout.write(line + "\n")
		fout.flush()
		a=1
	else:
		fout.write(line + "\n")
		fout.flush()
		a=1
	writelock.release()

found_24=set()

PROBE_INTERVAL = 1200
LARGE_PROBE_INTERVAL = 3600
PROBE_NODES = 400000
MAX_OUTAGE_INTERVAL = 21600


probenodes = Queue.PriorityQueue() #contains nodes that we repeatedly probe (every X sec) ordered by timestamp when to probe next

class KNode(object):

	def __init__(self, ip, port):
		self.ip = ip
		self.port = port

	def __eq__(self, other):
		return self.ip == other.ip and self.port == other.port

BOOTSTRAP_NODES = (
	KNode("router.bittorrent.com", 6881),
	KNode("dht.transmissionbt.com", 6881),
	KNode("router.utorrent.com", 6881)
)

BIND_IP = "0.0.0.0"
BIND_PORT = 0
MAX_BOOTSTRAP_LEN = 500

ufd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
ufd.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 30000000)
ufd.bind((BIND_IP, BIND_PORT))
socketqueue = Queue.Queue() ### internal queue only used on low-level socket interface

class SocketSender(Thread):
	def run(self):
		global socketqueue
		global one_time_error
		global multiple_errors
		global sleep_time
		slow_down_flag=False
		while True:
			time.sleep(sleep_time)
			(msg,address,message_type) = socketqueue.get()
			if int(address[1]) in [5060,1719,60333,5061]:
				continue
			try:
				ufd.sendto(msg,address)
			except Exception as e:
				time.sleep(10)
				try:
						ufd.sendto(msg,address)
				except Exception as e:
					#print "error sending packet again: Skipping",message_type,e,address
					a=1

ssender = SocketSender()
ssender.start()

class DHTListener(Thread):
	burned_ips = set()
	def run(self):
		while True:
			try:
				(data, address) = ufd.recvfrom(65536)
				msg = bdecode(data)
				self.on_message(msg, address)
			except:
				print str(time.time()) + " error."

	def on_message(self, msg, address):
		global probenodes
		global total_nat
		global ip_receiver
		global ip_watcher
		global sleep_time
		global last_backup_time
		global skip_count
		try:
			if msg["y"] == "r":
				if msg["r"].has_key("nodes"):
					self.process_find_node_response(msg, address)
				else:
					if msg["t"] == "xX":
						version = "NULL"
						try:
							version = binascii.hexlify(msg["v"])
						except:
							pass
						ip=address[0]
				port=address[1]
				ip_24=".".join(ip.split(".")[0:3])+".0"
				writeOutput(str(time.time()) + ";R;" + str(address[0]) + ":" + str(address[1]) + ";" + binascii.hexlify(msg["r"]["id"]) + ";" + version)
				if ip_24 in all_24:
					if ip not in ip_receiver:
						ip_receiver[ip]={}
					if port not in ip_receiver[ip]:
						ip_receiver[ip][port]=0
					ip_receiver[ip][port]=ip_receiver[ip][port]+1
					if ip not in ip_watcher:
						ip_watcher[ip]={}
						ip_watcher[ip]["last_probe"]=0
						ip_watcher[ip]["probe_count"]=0
						ip_watcher[ip]["cool_down"]=False
						ip_watcher[ip]["ports"]={}
					node_id=binascii.hexlify(msg["r"]["id"])
					if port not in ip_watcher[ip]["ports"]:
						ip_watcher[ip]["ports"][port]={}
						pinged=False
						if len(ip_watcher[ip]["ports"])>=2:
							if time.time()-ip_watcher[ip]["last_probe"]>=PROBE_INTERVAL:
								ip_watcher[ip]["cool_down"]=False
							if ip_watcher[ip]["probe_count"]>=10:
								if time.time()-ip_watcher[ip]["last_probe"]>=LARGE_PROBE_INTERVAL:
									ip_watcher[ip]["probe_count"]=0
							if ip_watcher[ip]["cool_down"]==False and ip_watcher[ip]["probe_count"]<10:
								for new_port in ip_watcher[ip]["ports"]:
										if port in [5060,1719,60333,5061]:
											skip_count=skip_count+1
										if port not in [5060,1719,60333,5061]:
											probenodes.put((time.time(),ip,int(new_port)))
								pinged=True

						if pinged==True:
							ip_watcher[ip]["cool_down"]=True
							ip_watcher[ip]["last_probe"]=time.time()
				if len(ip_receiver)%5000==0:
					total_nat=0
					for ip,port_data in ip_receiver.iteritems():
						if len(port_data)>=2:
							port_count=0
							for port,c in port_data.iteritems():
								if c>=2:
									port_count=port_count+1
							if port_count>=2:
								total_nat=total_nat+1


		except Exception as e:
			pass


	def process_find_node_response(self, msg, address):
		global bootstrapnodes
		global probenodes
		global total_discovered_nodes
		global sleep_time
		nodes = bt_messages.decode_nodes(msg["r"]["nodes"])
		total_discovered_nodes=total_discovered_nodes+1
		for node in nodes:
			(nid, ip, port) = node
			if len(nid) != 20: continue
			if port < 1 or port > 65535: continue
			n = KNode(ip, port) ###we have the nid here
			if port in [5060,1719,60333,5061]:
				skip_count=skip_count+1
			if port not in [5060,1719,60333,5061]:
				 ip_24=".".join(n.ip.split(".")[0:3])+".0"
				 if ip_24 in all_24:
					found_24.add(ip_24)
				 writeOutput(str(time.time()) + ";IP;" + str(n.ip) + ":" + str(n.port))
			 	 time.sleep(sleep_time)
				 socketqueue.put((bencode(bt_messages.generate_ping_message()), (n.ip, n.port),"ping_node"))

				 if bootstrapnodes.qsize() < MAX_BOOTSTRAP_LEN and msg["t"] == "aX":
					bootstrapnodes.put(n,False)


class DHTGetNodes(Thread):
	def run(self):
		global bootstrapnodes
		global probenodes
		global sleep_time
		bootstrapnodes = Queue.Queue(maxsize=MAX_BOOTSTRAP_LEN)
		iteration = 0

		while True:
			iteration += 1
			sleep(0.005)
			if bootstrapnodes.qsize() == 0:
				for b in BOOTSTRAP_NODES:
					self.send_find_node(b, "aX")
			else:
				self.send_find_node(bootstrapnodes.get())

			if probenodes.qsize() >= PROBE_NODES:
				print "GetNodes thread terminating."
				break ##terminate thread if we have sufficient number of nodes


	def send_find_node(self, target_node, nid=None):
		time.sleep(sleep_time)
		socketqueue.put((bencode(bt_messages.generate_find_node_message(nid)),(target_node.ip,target_node.port),"find_node"))


class DHTPinger(Thread):
	global sleep_time
	def run(self):
		while True:
			while(probenodes.qsize() == 0 or time.time() < probenodes.queue[0][0]):
				sleep(0.1)
			p = probenodes.get()
			ip=p[1]
			port=p[2]
			if int(port) in [5060,1719,60333,5061]:
					skip_count=skip_count+1
			if int(port) not in [5060,1719,60333,5061]:
					writeOutput(str(time.time()) + ";RP;" + str(ip) + ":" + str(port))
					time.sleep(sleep_time)
					socketqueue.put((bencode(bt_messages.generate_ping_message()),(ip,port),"ping_node_again"))


class ProbeNodeWatcher(Thread):
	def run(self):
		global probenodes
		global socketqueue
		global bootstrapnodes
		global all_24
		global total_discovered_nodes
		global one_time_error
		global multiple_errors
		global sleep_time
		global total_nat
		global skip_count
		global ip_watcher
		sleep_flag=False
		last_discovery=0
		g = DHTGetNodes()
		check_iteration=0
		slow_down_flag=False
		last_time=time.time()
		while True:
			if probenodes.qsize() < PROBE_NODES:
				if g.isAlive():
					a=1
				else:
					print "(re-)starting thread to get more nodes"
					g = DHTGetNodes()
					g.start()

			check=list(probenodes.queue)
			not_possible=0
			total=0
			not_yet=0
			still_pinging=0
			discovered=total_discovered_nodes-last_discovery
			last_discovery=total_discovered_nodes
			conntrack_count=int(subprocess.Popen("cat /proc/sys/net/netfilter/nf_conntrack_count", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0].strip())

			if conntrack_count>=30000:
				sleep_time=5
				sleep_flag=True
			if sleep_flag==True and conntrack_count<=15000:
				sleep_flag=False
				sleep_time=0

			if len(ip_watcher)==0:
				value="IP_watcher"+" "+str(len(ip_watcher))+" "+"NAT"+" "+str(total_nat)+" "+"Yet to ping"+" "+str(probenodes.qsize())+" "+"Size of bootstrap"+" "+str(bootstrapnodes.qsize())+" "+"Total discovered nodes"+" "+str(total_discovered_nodes)+" "+"Rate"+" "+str(discovered)+" "+"Socket queue"+" "+str(socketqueue.qsize())+" "+"Sleep time"+" "+str(sleep_time)+" "+"Conntrack"+" "+str(conntrack_count)+"Skip ports:  "+str(skip_count)
				print value
			if conntrack_count>=50000 and len(ip_watcher)!=0:
				value="IP_watcher"+" "+str(len(ip_watcher))+" "+"NAT"+" "+str(total_nat)+" "+str(total_nat/float(len(ip_watcher))*100)+" "+"Yet to ping"+" "+str(probenodes.qsize())+" "+"Size of bootstrap"+" "+str(bootstrapnodes.qsize())+" "+"Total discovered nodes"+" "+str(total_discovered_nodes)+" "+"Rate"+" "+str(discovered)+" "+"Socket queue"+" "+str(socketqueue.qsize())+" "+"Sleep time"+" "+str(sleep_time)+" "+"Conntrack"+" "+str(conntrack_count)+"Skip ports:  "+str(skip_count)
				CRED = '\033[91m'
				CEND = '\033[0m'
				print(CRED + value + CEND)
			else:
				print "IP_watcher",len(ip_watcher),"NAT",total_nat,"Yet to ping",probenodes.qsize(),"Size of bootstrap",bootstrapnodes.qsize(),"Total discovered nodes",total_discovered_nodes,"Rate",discovered,"Socket queue",socketqueue.qsize(),"Sleep time",sleep_time,"Conntrack",conntrack_count,"Skip ports",str(skip_count)
				sleep(1)
			if time.time()-last_time>=3600:
				last_time=time.time()



d = DHTListener()
d.start()

p = DHTPinger()
p.start()

c = ProbeNodeWatcher()
c.start()
