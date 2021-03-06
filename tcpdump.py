import sys, os, re
from datetime import datetime
from time import time
import thread

__all__ = [ 'TcpDump' ]

from config import *


TCPDUMP = 'tcpdump -qtlni %s tcp'
dump_skip = 2

# IP ks279501.kimsufi.com.2399 > drink.kerozene.de.33701: tcp 112
re_host_str = r'([a-zA-Z0-9_.-]+)\.([0-9a-zA-Z_-]+)'
re_host = re.compile(re_host_str)
re_output = re.compile('IP %s > %s: tcp ([0-9]+).*'%(re_host_str, re_host_str))


def get_dump(iface) :
	return os.popen(TCPDUMP%iface, 'r')

def parse_dump_line(l) :
	#print "<< %s >>"%l
	try :
		return re_output.match(l).groups()
	except :
		#print "RE FAILED", l
		return hostname, hostname


class TcpDump(object) :
	def __init__(self, iface) :
		self.dump = get_dump(iface)
		for i in xrange(dump_skip) :
			self.dump.readline()
		self.lock = thread.allocate_lock()
		self.counts = {}
		self.t = time()
		thread.start_new_thread(self._thread, tuple())
		self.quit=False
	def _thread(self) :
		while not self.quit :
			packet_from, port_from, packet_to, port_to, size = parse_dump_line(self.dump.readline())
			who, port = packet_from in (hostname, hostip) and (packet_to, port_to) or (packet_from, port_from)
			port = int(port)
			size = int(size)
			key = (who, port)
			self.lock.acquire()
			if key in self.counts :
				self.counts[key] += size
			else :
				self.counts[key] = size
			self.lock.release()
		self.dump.close()
	def __del__(self) :
		self.quit=True
	def get_counts(self) :
		self.lock.acquire()
		ret = self.counts
		ret_t = self.t
		self.counts = {}
		self.t = time()
		self.lock.release()
		return ret, self.t-ret_t

