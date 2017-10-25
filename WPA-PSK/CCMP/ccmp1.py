import hmac,hashlib,binascii
from binascii import a2b_hex
from binascii import b2a_hex
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
  

######################################
# Only work for TKIP
######################################


'''
passPhrase="10zZz10ZZzZ"
ssid        = "Netgear 2/158"
A           = "Pairwise key expansion\0"
APmac       = a2b_hex("001e2ae0bdd0")
Clientmac   = a2b_hex("cc08e0620bc8")
ANonce      = a2b_hex("79f97cac4db0b603f8f0645242543ac6dcedcf83f52646f3e61e6415720afcc2")
SNonce      = a2b_hex("60eff10088077f8b03a0e2fc2fc37e1fe1f30f9f7cfbcfb2826f26f3379c4318")
B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce)
data = a2b_hex("0103005ffe01090020000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
pmk = a2b_hex("01b809f9ab2fb5dc47984f52fb2d112e13d84ccb6b86d4a7193ec5299f851c48")
'''




def PRF512(pmk,A,B):
  ptk1 = hmac.new(pmk, binascii.a2b_qp(A)+ B + chr(0), hashlib.sha1).digest()
  ptk2 = hmac.new(pmk, binascii.a2b_qp(A)+ B + chr(1), hashlib.sha1).digest()
  ptk3 = hmac.new(pmk, binascii.a2b_qp(A)+ B + chr(2), hashlib.sha1).digest()
  ptk4 = hmac.new(pmk, binascii.a2b_qp(A)+ B + chr(3), hashlib.sha1).digest()
  return ptk1+ptk2+ptk3+ptk4[0:4]


passPhrase = "1234567890"
ssid = "wpatest"
A = "Pairwise key expansion\0"
APmac = a2b_hex("08100c000c24")
Clientmac = a2b_hex("5001d9a68533")
ANonce = a2b_hex("79f97cac4db0b603f8f0645242543ac6dcedcf83f52646f3e61e6415830afcc2")
SNonce = a2b_hex("b4e2f47ada68a6c78a4fa1730b8abc36f827243da309cfba66ef963652b21391")
B = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce)

print b2a_hex(B)
#### wpa_passphrase TP-LINK_4F6C90 LINUXZSJ
psk = pbkdf2_hex(passPhrase,ssid,4096,256)[:64]
pmk = a2b_hex(psk)

print "PMK",psk
ptk = PRF512(pmk,A,B)
print "PTK:",b2a_hex(ptk)




data = a2b_hex("0103007502010a00000000000000000000b4e2f47ada68a6c78a4fa1730b8abc36f827243da309cfba66ef963652b21391000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac040100000fac040100000fac020000")
mic = hmac.new(ptk[0:16],data,hashlib.sha1) 
print "EAPOL 2 MIC: 15f768c0b36423e50fd7fefdec007ac1"
print "Calc    MIC:",mic.hexdigest()[0:32]


data = a2b_hex("010300970213ca001000000000000000018a8c8b619c68e3a491d028387842b43d9d6a622273a8eaf69f2e88503cf243b48a8c8b619c68e3a491d028387842b43de5040000000000000000000000000000000000000000000000000000000000000038a8f548bc87b0e26f6900847d6cefa414ce91c3bec6bd47eedcea63ef5d4deaeaedbebee9bf90ab5523c735edac04a77d1958a4392db206e3")
mic = hmac.new(ptk[0:16],data,hashlib.sha1)
print "EAPOL 3 MIC: 536c965605ed8d7b3c2530db5d4dcac3"
print "Calc    MIC:",mic.hexdigest()[0:32]


data = a2b_hex("0103005f02030a0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
mic = hmac.new(ptk[0:16],data,hashlib.sha1) 
print "EAPOL 4 MIC: 6dc0a73161932ee9790778a45a2fc6f8"
print "Calc    MIC:",mic.hexdigest()[0:32]
