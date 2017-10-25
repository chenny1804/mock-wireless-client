#-*-coding:utf-8-*-
from scapy.all import *
from time import sleep
import sys,random
from  init_interface import set_wl_channel,set_wl_monitor
class test_wlan_frame():
	def __init__(self,radioband,clientmac,interface,ssid=None,apmac=None):
		self.radioband=radioband
		self.clientmac=clientmac
		self.iface=interface
		self.ssid=ssid
		self.apmac=apmac
		self.probpkt=self.__prob_init()
		if self.apmac==None:
			self.apmac=self.__getAPmac()
		self.authpkt=self.__auth_init()
		self.assocpkt=self.__assoc_init()
		self.disassocpkt=self.__disassoc_init()
		self.reassocpkt=self.__reassoc_init()
	def __getAPmac(self):
		while True:
			#print "send prob"
			rppkt,unans=srp(self.probpkt,iface=self.iface,timeout=1)
			#print "pkt-len:",len(rppkt),"unans",len(unans)
			if len(rppkt) > 0 and len(unans)==0:
			#for i in rppkt[0]:
				i=rppkt[0][1]
				if i.info == self.ssid:
					print "\t\t\t\t\t\t\t",self.ssid,"-->",i.addr2
					return i.addr2
	def __prob_init(self):
		if self.radioband ==1:
			#prob=rdpcap("probreq24.pcap")[0]
			prob=rdpcap("5.pcap")[0]
		elif self.radioband==0:
			#prob=rdpcap("probreq5g.pcap")[0]
			#prob=rdpcap("new5gprob.pcap")[0]
			#prob=rdpcap("notsurportrate.pcap")[0]
			#prob=rdpcap("notsuportrate_gn.pcap")[0]
			#prob=rdpcap("prob5g11ac-notsurpot-11ac.pcap")[0]
			prob=rdpcap("4.pcap")[0]
		else:
			print "Please set radioband"
		prob.addr2=self.clientmac
		prob[Dot11Elt][0].len=len(self.ssid)
		prob.info=self.ssid
		return prob
	def __auth_init(self):
		if self.radioband ==1:
			auth=rdpcap("authreq24.pcap")[0]
		elif self.radioband==0:
			auth=rdpcap("authreq5g.pcap")[0]
		else:
			print "Please set radioband"
		auth.addr2=self.clientmac
		auth.addr1=self.apmac
		auth.addr3=self.apmac
		return auth
	def __assoc_init(self):
		if self.radioband ==1:
			assoc=rdpcap("assocreq24.pcap")[0]
		elif self.radioband==0:
			assoc=rdpcap("assocreq5g.pcap")[0]
		else:
			print "Please set radioband"
		assoc.addr2=self.clientmac
		assoc.addr1=self.apmac
		assoc.addr3=self.apmac
		assoc[Dot11Elt][0].len=len(self.ssid)
		assoc.info=self.ssid
		return assoc
	def __reassoc_init(self):
		if self.radioband ==1:
			reassoc=rdpcap("reassocreq24.pcap")[0]
		elif self.radioband==0:
			reassoc=rdpcap("reassocreq24.pcap")[0]
		else:
			print "Please set radioband"
		reassoc.addr2=self.clientmac
		reassoc.addr1=self.apmac
		reassoc.addr3=self.apmac
		reassoc[Dot11Elt][0].len=len(self.ssid)
		reassoc.info=self.ssid
		reassoc.listen_interval=2
		reassoc[Dot11ReassoReq].current_AP="00:00:1c:88:88:88"
		return reassoc
	def __disassoc_init(self):
		if self.radioband ==1:
			disassoc=rdpcap("disassoc24.pcap")[0]
		elif self.radioband==0:
			disassoc=rdpcap("disassoc5g.pcap")[0]
		else:
			print "Please set radioband"
		disassoc.addr2=self.clientmac
		disassoc.addr1=self.apmac
		disassoc.addr3=self.apmac
		disassoc.info=self.ssid
		return disassoc			
	def __send_frame(self,pkt):
		rsppkt,unans=srp(pkt,iface=self.iface,timeout=1)
		return rsppkt,unans
	def __send_prob(self):
		rsppkt,unans=self.__send_frame(self.probpkt)
		if len(rsppkt)>0 and len(unans) == 0:
			print "\t\t\t\t\t\t\t--------Prob OK"
		else:
			print "\t\t\t\t\t\t\t--------Prob No resp"
	def __send_auth(self):
		rsppkt,unans=self.__send_frame(self.authpkt)
		if len(rsppkt)>0 and len(unans) == 0:
			if rsppkt[0][1].status == 0:
				print "\t\t\t\t\t\t\t------auth OK"
			else:
				print "\t\t\t\t\t\t\t[<<<<auth status>>>>]",rsppkt[0][1].status
		else:
			print "\t\t\t\t\t\t\t--------Auth No resp"

	def __send_assoc(self):
		rsppkt,unans=self.__send_frame(self.assocpkt)
		if len(rsppkt)>0 and len(unans) == 0:
			if rsppkt[0][1].status == 0:
				print "\t\t\t\t\t\t\t------assoc OK"
				return True
			else:
				print "\t\t\t\t\t\t\t[<<<<assoc status>>>>]",rsppkt[0][1].status
		else:
			print "\t\t\t\t\t\t\t--------Assoc No resp"
		return False
	def __send_reassoc(self):
		rsppkt,unans=self.__send_frame(self.reassocpkt)
		if len(rsppkt)>0 and len(unans) == 0:
			if rsppkt[0][1].status == 0:
				print "\t\t\t\t\t\t\t------assoc OK"
				return True
			else:
				print "\t\t\t\t\t\t\t[<<<<assoc status>>>>]",rsppkt[0][1].status
		else:
			print "\t\t\t\t\t\t\t--------Assoc No resp"
		return False
	def __send_disassoc(self):
		sendp(self.disassocpkt,iface=self.iface,count=1)
		return True
	def send_assoc(self):
		self.__send_assoc()
	def test_suit_normal(self):
		self.__send_prob()
		self.__send_auth()
		self.__send_assoc()
	def test_suit_no_porb(self):
		self.__send_auth()
		self.__send_assoc()
	def test_assoc_num(self):
		self.__send_auth()
		return self.__send_assoc()
	def test_disassoc(self):
		self.__send_auth()
		self.__send_assoc()
		sleep(1);
		self.__send_disassoc()
	def test_auth(self):
			self.__send_auth()
	def test_reassoc(self):
		self.__send_auth()
		self.__send_reassoc()
	def test_prob(self):
		self.__send_prob()
def get_maclist(COUNT):
	num=["1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
	Maclist=[]
	count=1
	randommac=random.choice(num)
	#randommac='7'
	for i in num:
		for j in num:
			for k in num:
				if count > COUNT:
					return Maclist
					break
				Maclist.append("00:00:1C:35:"+randommac+i+":"+j+k)
				count=count+1
def  test_assoc_num():
	maclist=get_maclist(STA_NUM)
	succescount=0
	print "maclist first mac:",maclist[0],"maclist last mac:",maclist[-1]
	for mac in maclist:
		Test1=test_wlan_frame(BAND,mac,INTERFACE,SSID,AP_MAC)
		#Test1.test_suit_no_porb()
		#Test1.test_suit_normal()
		if Test1.test_assoc_num():
			succescount=succescount+1
		print "\t\t\t\t\t\t\tMAC: ",mac," assoc"
		print "\t\t\t\t\t\t\tassoc OK NUM----:",succescount
		sleep(0.5)	
def test_assoc_status():
	maclist=get_maclist(STA_NUM)
	succescount=0
	print "maclist first mac:",maclist[0],"maclist last mac:",maclist[-1]
	for mac in maclist:
		i=0
		while i < 4:
			Test1=test_wlan_frame(BAND,mac,INTERFACE,SSID,AP_MAC)
			if Test1.test_disassoc():
				print "send disaccoc ok"
			i=i+1
def test_reassoc():
	mac="08:10:11:22:33:55" 		#station's MAC
	current_AP="08:10:1c:00:00:45"		#current connect AP mac
	Test1=test_wlan_frame(BAND,mac,INTERFACE,SSID,AP_MAC)
	Test1.reassocpkt[Dot11ReassoReq].current_AP=current_AP
	Test1.test_reassoc()
def test_auth():
	mac="08:10:11:22:33:55" 		#station's MAC
	current_AP="08:10:1c:00:00:45"		#current connect AP mac
	Test1=test_wlan_frame(BAND,mac,INTERFACE,SSID,AP_MAC)
	Test1.send_assoc()
def test_prob():
	mac="08:10:11:22:33:55"
	Test1=test_wlan_frame(BAND,mac,INTERFACE,SSID,AP_MAC)
	while 1:
		Test1.test_prob()
def test_prob_ssid():
	mac="08:10:11:22:33:55"
	count=0
	while count < 3000:
		SSID="test_ssid_"+str(count)
		Test1=test_wlan_frame(BAND,mac,INTERFACE,SSID,AP_MAC)
		Test1.test_prob()
		count=count+1
def test_porb_nossid():
	mac="08:10:11:22:33:55"
	count=0
	while count < 10:
		SSID=""
		Test1=test_wlan_frame(BAND,mac,INTERFACE,SSID,AP_MAC)
		Test1.test_prob()
		count=count+1		
if __name__== "__main__":
	BAND=1												#channel band value: 0 is 5G  and 1 is 2.4G 
	INTERFACE="mon0"                        #interface of send frame
	SSID="_NETCORE-5G-TESTING"					#AP's SSID
	#AP_MAC="00:00:1c:00:85:23"		#AP's MAC
	AP_MAC="08:10:00:88:12:41"
	CHANNEL=11
	set_wl_channel(INTERFACE,CHANNEL)
	#STA_NUM=200								#mock the number of station
	#set_wl_monitor()
	#test_auth()
	#test_assoc_num()
	#test_assoc_status()
	#test_reassoc()
	
	#test_prob()
	test_prob_ssid()
	#test_porb_nossid()

