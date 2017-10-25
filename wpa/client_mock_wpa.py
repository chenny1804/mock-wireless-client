#-*-coding:utf-8-*-
import hmac,hashlib,binascii
from scapy.all import *
from time import sleep
import sys,random
from binascii import a2b_hex,b2a_hex
from  init_interface import set_wl_channel,set_wl_monitor
from struct import Struct
from operator import xor
from itertools import izip, starmap

#################################
##### https://github.com/mitsuhiko/python-pbkdf2/blob/master/pbkdf2.py
#################################
_pack_int = Struct('>I').pack


def pbkdf2_hex(data, salt, iterations=1000, keylen=24, hashfunc=None):
    """Like :func:`pbkdf2_bin` but returns a hex encoded string."""
    return pbkdf2_bin(data, salt, iterations, keylen, hashfunc).encode('hex')


def pbkdf2_bin(data, salt, iterations=1000, keylen=24, hashfunc=None):
    """Returns a binary digest for the PBKDF2 hash algorithm of `data`
    with the given `salt`.  It iterates `iterations` time and produces a
    key of `keylen` bytes.  By default SHA-1 is used as hash function,
    a different hashlib `hashfunc` can be provided.
    """
    hashfunc = hashfunc or hashlib.sha1
    mac = hmac.new(data, None, hashfunc)
    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(x)
        return map(ord, h.digest())
    buf = []
    for block in xrange(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(salt + _pack_int(block))
        for i in xrange(iterations - 1):
            u = _pseudorandom(''.join(map(chr, u)))
            rv = starmap(xor, izip(rv, u))
        buf.extend(rv)
    return ''.join(map(chr, buf))[:keylen]

def PRF512(pmk,A,B):
	ptk1 = hmac.new(pmk, binascii.a2b_qp(A)+ B + chr(0), hashlib.sha1).digest()
	ptk2 = hmac.new(pmk, binascii.a2b_qp(A)+ B + chr(1), hashlib.sha1).digest()
	ptk3 = hmac.new(pmk, binascii.a2b_qp(A)+ B + chr(2), hashlib.sha1).digest()
	ptk4 = hmac.new(pmk, binascii.a2b_qp(A)+ B + chr(3), hashlib.sha1).digest()
	return ptk1+ptk2+ptk3+ptk4[0:4]
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
			prob=rdpcap("probreq24.pcap")[0]
			#prob=rdpcap("5.pcap")[0]
			#prob=rdpcap("24probrequest.pcap")[0]
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
def handshake(pkt):
	#global psk,pmk,ptk
	eapol_2=rdpcap("eapol-2.pcap")
	eapol_4=rdpcap("eapol-4.pcap")
	global PTK
	if b2a_hex(pkt[EAPOL].load[1:3]) == '008a' and pkt.addr1==STA_MAC and pkt.addr2==AP_MAC:
		#pkt.show()
		ANonce=b2a_hex(pkt[EAPOL].load[13:45])
		#ANonce=a2b_hex("8a8c8b619c68e3a491d028387842b43d9d6a622273a8eaf69f2e885038f343b4")
		print "ANonce:",ANonce
		PTK=get_ptk(ANonce)
		#print "PMK",psk
		print "PTK:",b2a_hex(PTK)
		
		mic="0"*32
		eapol_2[0][EAPOL].addr1=eapol_2[0][EAPOL].addr3=AP_MAC
		eapol_2[0][EAPOL].addr2=STA_MAC
		data=eapol_2[0][EAPOL].load[:77]+a2b_hex(mic)+eapol_2[0][EAPOL].load[93:]
		if len(data) == len(eapol_2[0][EAPOL].load):
			print "load length eq"
		else:
			print "load length no eq"
		data=a2b_hex('01030075')+data
		print b2a_hex(data)
		mic = hmac.new(PTK[0:16],data,hashlib.sha1) 
		print "MIC:",mic.hexdigest()[0:32]
		newmic=a2b_hex(mic.hexdigest()[0:32])
		print "eapol-2 mic",b2a_hex(newmic)
		#newmic=a2b_hex("d28ac2221e0bf70f09849d57dd1585ba")
		eapol_2[0][EAPOL].load=eapol_2[0][EAPOL].load[:77]+newmic+eapol_2[0][EAPOL].load[93:]
		#eapol_2[0].show()
		#print "len:",len(eapol_2[0][EAPOL].load)
		#rsppkt,unans=srp(eapol_2[0],iface=INTERFACE,retry=10)
		sendp(eapol_2[0],iface=INTERFACE,count=1)
		
		mic='0'*32
		eapol_4[0][EAPOL].addr1=eapol_4[0][EAPOL].addr3=AP_MAC
		eapol_4[0][EAPOL].addr2=STA_MAC
		data=eapol_4[0][EAPOL].load[:77]+a2b_hex(mic)+eapol_4[0][EAPOL].load[93:]
		if len(data) == len(eapol_4[0][EAPOL].load):
			print "load length eq"
		else:
			print "load length no eq"
		data=a2b_hex('0103005f')+data
		mic = hmac.new(PTK[0:16],data,hashlib.sha1) 
		newmic=a2b_hex(mic.hexdigest()[0:32])
		print "eapol-4 mic:",b2a_hex(newmic)
		#newmic=a2b_hex("d28ac2221e0bf70f09849d57dd1585ba")
		eapol_4[0][EAPOL].load=eapol_4[0][EAPOL].load[:77]+newmic+eapol_4[0][EAPOL].load[93:]
		sendp(eapol_4[0],iface=INTERFACE,count=1)
	if b2a_hex(pkt[EAPOL].load[1:3]) == '13ca' and pkt.addr1==STA_MAC :
		print "eapol-3"	
		'''
		mic='00000000000000000000000000000000'
		
		data=eapol_4[0][EAPOL].load[:77]+a2b_hex(mic)+eapol_4[0][EAPOL].load[93:]
		if len(data) == len(eapol_4[0][EAPOL].load):
			print "load length eq"
		else:
			print "load length no eq"
		data=a2b_hex('0103005f')+data
		print b2a_hex(data)
		mic = hmac.new(PTK[0:16],data,hashlib.sha1) 
		print "MIC:",mic.hexdigest()[0:32]
		newmic=a2b_hex(mic.hexdigest()[0:32])
		print "New MIC",b2a_hex(newmic)
		#newmic=a2b_hex("d28ac2221e0bf70f09849d57dd1585ba")
		eapol_4[0][EAPOL].load=eapol_4[0][EAPOL].load[:77]+newmic+eapol_4[0][EAPOL].load[93:]
		sendp(eapol_4[0],iface=INTERFACE,count=1)
		'''
def get_ptk(ANonce):
	ANonce=a2b_hex(ANonce)
	#print "ANonce:",ANonce
	SNonce=a2b_hex("b4e2f47ada68a6c78a4fa1730b8abc36f827243da309cfba66ef963652b21391")
	A = "Pairwise key expansion\0"
	APmac=a2b_hex(AP_MAC.replace(":",""))
	#APmac=a2b_hex("08100c000c24")
	print "APmac:",AP_MAC.replace(":","")
	Clientmac=a2b_hex(STA_MAC.replace(":",""))
	#Clientmac=a2b_hex("5001d9a685da")
	print "Clientmac:",STA_MAC.replace(":","")
	B = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce)
	print b2a_hex(B)
	psk = pbkdf2_hex(PASSPHRASE,SSID,4096,256)[:64] 
	pmk = a2b_hex(psk)
	ptk = PRF512(pmk,A,B)
	print "PMK",psk
	print "PTK:", hmac.new(ptk).hexdigest()
	return ptk
def test_wpa2():
	Test1=test_wlan_frame(BAND,STA_MAC,INTERFACE,SSID,AP_MAC)
	Test1.test_suit_normal()
	sniff(count=1,iface="mon0",prn=handshake,lfilter=lambda x: x.haslayer(EAPOL))	
if __name__== "__main__":
	BAND=1												#channel band value: 0 is 5G  and 1 is 2.4G 
	INTERFACE="mon0"                        #interface of send frame
	SSID="wpatest"
	PASSPHRASE="1234567890"					#AP's SSID
	#AP_MAC="00:00:1c:00:85:23"		#AP's MAC
	AP_MAC="08:10:0c:00:0c:24"
	STA_MAC="50:01:d9:a6:85:da"
	CHANNEL=13
	set_wl_channel(INTERFACE,CHANNEL)
	#STA_NUM=200								#mock the number of station
	#set_wl_monitor()
	#test_auth()
	#test_assoc_num()
	#test_assoc_status()
	#test_reassoc()
	
	#test_prob()
	#test_prob_ssid()
	#test_porb_nossid()
	test_wpa2()
	#print b2a_hex(get_ptk("e179e613f956db35a36b9bc707c1116c084dfdee6868f463363a6898746dae36"))

