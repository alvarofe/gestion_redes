import os
import sys
import nmap

from fabric.api import *
from server import * 

active_hosts = []
cmd = ['hostname',"ifconfig en1 | grep 'inet ' | awk '{ print $2 }' | sed 's/addr://'",
		'whoami','uname -a','uptime']
def start():
	while True:
		menu()

def run_command(command):
    try:
        with hide('running', 'stdout', 'stderr'):
            if command.strip()[0:5] == "sudo":
                results = sudo(command)
            else:
                results = run(command)
    except:
        results = 'Error'
    return results
def check_hosts():
    ''' Checks each host to see if it's running '''
    try:
    	global active_hosts
    	for host, result in execute(run_command, "uptime", hosts=env.hosts).iteritems():
        	if result.succeeded:
        		active_hosts.append(server(host,22,active=True))
    except Exception:
    	pass

def read_host_file():
	for line in open('hostlist','r').readlines():
		if line[0] != "#":
			host,passw = line.split()
			env.hosts.append(host)
			env.passwords[host] = passw

def menu():
	global active_hosts
	print "\n"
	for num, desc in enumerate(["Check Hosts", "Update Hosts", "List Hosts", "Host Details", "See Open Ports", "Open Shell", "Exit"]):
		print "[" + str(num) + "] " + desc

	while True:
		raw_choice = raw_input("#> ")
		if raw_choice.isdigit():
			choice = int(raw_choice)
			break
	if choice == 0:
		read_host_file()
		check_hosts()
	elif choice ==1 :
		active_hosts = []
		env.hosts = []
		env.passwords ={}
		read_host_file()
		check_hosts()
	elif choice == 2:
		print "\n\n----------Active Hosts-------------\n"
		for host in active_hosts:
			host.details()
		print "\n-----------------------------------\n"

	elif choice == 3:
		host_information = {}
		for host in env.hosts:
			host_information[host] = {}
		for i in cmd:
			for h, result in execute(run_command, i, hosts=env.hosts).iteritems():
				host_information[h][i] = result
		for host in host_information:
			print "\n\n[+] Host           : %s" % (host)
			print " - Active          : %r" % True
			print " - R - Hostname    : %s" % host_information[host]['hostname']
			print " - R - IP Address  : %s" % host_information[host]["ifconfig en1 | grep 'inet ' | awk '{ print $2 }' | sed 's/addr://'"]
			print " - R - User        : %s" % host_information[host]['whoami']
			print " - uname           : %s" % host_information[host]['uname -a']
			print " - uptime          :%s"  % host_information[host]['uptime']

	elif choice == 4:
		nm = nmap.PortScanner()
		host = int(raw_input("Host: "))
		try:
			ip = env.hosts[host].split(":")[0].split('@')[1]
			nm.scan(hosts=ip,arguments='-sT -Pn')
			print "\n\n[+] Host           : %s" % (ip)
			for key in nm[ip]['tcp']:
				print " - %s: %s/%s  " % (str(key),nm[ip]['tcp'][key]['name'],nm[ip]['tcp'][key]['state'])
		except IndexError:
			print "host number is wrong"

	elif choice == 5:
		try:
			host = int(raw_input("Host: "))
			execute(open_shell, host=env.hosts[host])
		except IndexError:
			print "host number is wrong"
	elif choice == 6:
		sys.exit(0)
	return;		