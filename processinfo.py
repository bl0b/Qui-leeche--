import sys, os
import socket

from config import hostname

__all__ = [
	'get_processes',
	'get_process_program',
	'get_processes_and_programs',
	'get_process_sockets',
	'get_sockets',
	'get_process_remote_peers',
	'get_pids_of'
]

hostip = socket.gethostbyname(hostname)


def get_processes() :
	def filter_process(x) :
	    try :
	            int(x)
	            return True
	    except :
	            return False
	return filter(filter_process, os.listdir('/proc'))

def get_process_program(p) :
	try :
		return os.path.basename(open('/proc/%s/cmdline'%p).read().split('\x00')[0])
	except :
		return '(none)'

def get_processes_and_programs() :
	return map(lambda pid : (get_process_program(pid), pid), get_processes())

def get_process_sockets(p) :
	ret = []
	for fd in os.listdir('/proc/%s/fd'%p) :
		try :
			l = os.readlink('/proc/%s/fd/%s'%(p, fd))
			if l.startswith('socket:') :
				ret.append(l[8:-1])
		except :
			pass
	return ret

def get_sockets() :
	return dict( [ (k[9], k) for k in map(str.split, open('/proc/net/tcp').readlines()[1:]) ] )

def get_process_remote_peers(p, socks) :
	psocks = get_process_sockets(p)
	ret = []
	def unpack_ip(ipstr) :
		return socket.inet_ntoa('%c%c%c%c'%tuple([int(ipstr[2*i:2*i+2], 16) for i in xrange(3,-1,-1)]))
	def unpack_port(portstr) :
		return int(portstr, 16)
	for sock in psocks :
		try :
			hp1, hp2 = socks[sock][1:3]
			host1, port1 = hp1.split(':')
			host2, port2 = hp2.split(':')

			host1 = unpack_ip(host1)
			host2 = unpack_ip(host2)
			port1 = unpack_port(port1)
			port2 = unpack_port(port2)
			
			if host1!=hostip :
				ret.append((host1, port1))
			
			if host2!=hostip :
				ret.append((host2, port2))

		except Exception, e :
			pass
	return ret


def get_pids_of(processes, pname) :
	ret = []
	for pn, pid in processes :
		if pn.startswith(pname) :
			ret.append(pid)
	return ret




