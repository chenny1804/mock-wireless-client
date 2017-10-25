import os,sys
from time import sleep
def get_interface():
	lines=os.popen("ifconfig -a\n")
	return lines
def check_interface():
	for i in get_interface().readlines():
		if i.find("mon0") > -1:
			return True
		else:
			continue
	return False
def  find_wireless_interface():
	for i in get_interface().readlines():
		if i.find("wlan") > -1:
			wlinterface=i.split(" ")[0]
			print "get the wirlese interface :%s"%(wlinterface)
			return wlinterface
		else:
			continue
		return False
def set_wl_monitor():
	if check_interface():
		print "mon0 is exit! "
		return 
	wl=find_wireless_interface()
	if not wl:
		print "wireless can't  be find,Please check Interface!"
		sys.exit()
	os.system("airmon-ng start "+wl+"\n")
	os.system("ifconfig "+wl+" down\n")
	if check_interface():
		sleep(1)
		os.system(" service network-manager stop\n")
		sleep(2)
		os.system("iwconfig mon0 mode monitor\n")
		os.system("ifconfig mon0 up\n")
	else:
		print "mon0 don't get up"
		sys.exit()
	return 
def set_wl_channel(iface,channel):
	os.system("iwconfig mon0 channel "+str(channel)+"\n")
def  cancel_wl_monitor():
		os.system("airmon-ng stop mon0 \n")
		os.system(" service network-manager start\n")
def useage():
	print "USEAGE:"
	print "\tpython init_interface S\t\tSet Monitor for wlan interface "
	print "\tpython init_interface C\t\tCancel Monitor for wlan interface"
if __name__== "__main__":
	if  sys.argv == 0:
		useage()
		sys.exit(0)
	d=sys.argv[1]
	if d== "S":
		set_wl_monitor()
	elif d== "C":
		cancel_wl_monitor()
	else:
		useage()
		sys.exit(0)
