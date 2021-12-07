import hashlib as hl
import random
from functions2 import *


#Global Vars
timeout = 5
BUFFER = 2048
comm_length = 16
priv_key_identifier = "_priv_key.pem"
pub_key_identifier = "_pub_key.pem"


#Methods
def dice_roll():
	return bytes(str(random.randint(1,6)),"utf-8")

def comm(m,r):
	hash = hl.sha256()
	hash.update(bytes(m+r,'utf-8'))
	return hash.hexdigest()

def verify_comm(m,r,c):
	return comm(m,r) == c


import rsa as r
def gen_keys(name):
	public_key,private_key = r.newkeys(1024)
	with open("keys/"+name+priv_key_identifier,"wb") as f:
		f.write(private_key.save_pkcs1())
	with open("keys/"+name+pub_key_identifier,"wb") as f:
		f.write(public_key.save_pkcs1())

def sign_mess(message,name):
	message = bytes(str(message),"utf-8")
	filename = 'keys/'+name+priv_key_identifier
	with open(filename, 'rb') as f:
		private_key = r.PrivateKey.load_pkcs1(f.read())
		signed_mess = r.sign(message,private_key,'SHA-256')
	return signed_mess

def verify_sign(mess,name,sign):
	byte_mess = bytes(str(mess),'utf-8')
	with open("keys/"+name+pub_key_identifier,"rb") as f:
		public_key = r.PublicKey.load_pkcs1(f.read())
		check_signture = r.verify(byte_mess,sign,public_key)
	return check_signture

def aXORb(a,b):
	d = int(a)^int(b) % 6+1
	return d


