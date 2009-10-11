#!/usr/bin/env python

import sys, os, re
from datetime import datetime
from time import time, sleep
import socket

from config import *
from processinfo import *
from tcpdump import *

refresh = 1	# seconds

interface = '<UNSET>'


try :
	sys.argv.index('--no-ssh')
	filters = []
except :
	users = list(set(os.listdir('/home'))-ssh_no_users)
	filters = map(lambda x : 'sshd: '+x, users)

filters += default_filters




def init() :
	global refresh, interface, filters
	try :
		r = sys.argv.index('-r')+1
		refresh = float(sys.argv[r])
	except Exception, e :
		#print e
		pass
	try :
		i = sys.argv.index('-i')+1
		interface = sys.argv[i]
	except Exception, e :
		#print e
		pass
	try :
		f = sys.argv.index('-f')+1
		filters += sys.argv[f].split(',')
	except Exception, e :
		#print e
		pass


dnscache = {}

def ip2name(ip) :
	try :
		return dnscache[ip]
	except :
		try :
			dnscache[ip] = socket.gethostbyaddr(ip)[0]
		except socket.herror :
			dnscache[ip] = ip
		return dnscache[ip]


def usage() :
	print """Qui leeche ?

   -r refresh_time			how often to refresh display (default 1 seconds, floats allowed)
   -i interface				which interface to spy on
   -f program_name,program_name...	group together peers for those programs (will be displayed as "PROC program_name" instead of inet peer)
   --no-ssh				DON'T filter by (see -f) SSH sessions
"""

class Chrono(object) :
	def __init__(self) :
		self.data=time()
	def __repr__(self) :
		return str(float(self))
	def __str__(self) :
		return self.__repr__()
	def __float__(self) :
		return time()-self.data

if __name__=='__main__' :
	init()
	tcpdump = TcpDump(interface)
	if interface=='<UNSET>' :
		usage()
		sys.exit(0)
	sleep(refresh)
	ppf = {}
	for f in filters :
		ppf[f] = '\x1b[1m%s\x1b[m'%f
	while True :
		t1 = time()
		new_packet_counts, interval = tcpdump.get_counts()
		#print '\x1B[2J\x1B[0;0H'
		filt_peers = {}
		c=Chrono()
		propro = get_processes_and_programs()
		#print "get_processes_and_programs", float(c)
		c=Chrono()
		socks = get_sockets()
		#print "get_sockets", float(c)
		c=Chrono()
		for progname in filters :
			filt_peers[progname] = []
			pids = get_pids_of(propro, progname)
			for pid in pids :
				filt_peers[progname] += get_process_remote_peers(pid, socks)
			filt_peers[progname] = dict(zip(filt_peers[progname], xrange(len(filt_peers[progname]))))
		#print "filters", float(c)
		#print filt_peers
		packet_counts = dict([(ppf[f], 0.) for f in filters])
		#print new_packet_counts
		scale = 1./(interval*1024.)
		for who, port in new_packet_counts.keys() :
			#try :
				#new_packet_counts[who]+=packet_counts[who]
			#except :
				#pass
			key = (who, port)
			new_packet_counts[key]*=scale
			strip = False
			for f in filters :
				if key in filt_peers[f] :
					#print f, who, port
					packet_counts[ppf[f]] += new_packet_counts[key]
					strip = True
					break
			if not strip :
				n = ip2name(who)
				if n in packet_counts :
					packet_counts[n] += new_packet_counts[key]
				else :
					packet_counts[n] = new_packet_counts[key]

		#packet_counts = new_packet_counts
		new_packet_counts = {}
		t0 = time()
		who_sorted = sorted(packet_counts.keys(), key=lambda a : -packet_counts[a])
		total = reduce(float.__add__, packet_counts.values())
		percent = 100./total
		whoswho = '\n'.join(['%-63s\t%8.2f kB/s    %5.1f%%'%(k, packet_counts[k], packet_counts[k]*percent) for k in who_sorted if packet_counts[k]!=0.])
		print '\x1B[2J\x1B[0;0H'+str(datetime.now())
		print
		print "Qui leeche ? (computed in %5.3f seconds)"%(time()-t1)
		print "Total %7.1f kB/s"%total
		print
		print "%s\r"%whoswho
		#sys.exit(0)
		dt = refresh+refresh-interval
		sleep(dt>1 and 1 or refresh)

