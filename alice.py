import socket,random, pickle, time
from functions2 import *
from rsa.pkcs1 import VerificationError


s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.settimeout(15)
s.connect((socket.gethostname(), 1234))

#gen_keys("Alice")

alice_a = str(random.getrandbits(3))
alice_r = str(random.getrandbits(comm_length))

"""
Send a signed commitment
"""

c = comm(alice_a, alice_r)
signed_comm = sign_mess(c,'Alice')
d = {
	"signed_comm": signed_comm,
	"comm":c
	}
msg_send = pickle.dumps(d)
#input("Press any key to send...")
s.sendall(msg_send)



"""
Get Bobs signed number
"""
msg = b""

msg_recv = s.recv(BUFFER)
msg = msg+msg_recv


payload = pickle.loads(msg)
bob_number = payload['number']
signed_mess = payload['signed_mess']

try:
	verification = verify_sign(bob_number, 'Bob',signed_mess)
	print("Message was signed with algorithm: "+verification)
except VerificationError:
	print("Verification failed!\nMessage not from Bob, breaking")
finally:
	pass

"""
Alice send an opened commitment
"""
d = {
	"alice_number": alice_a,
	"alice_salt":alice_r
	}
msg_send = pickle.dumps(d)
s.send(msg_send)


"""
Computing the number
"""
if verification:
	d = aXORb(alice_a,bob_number)
	print("Compute d = (alice_number ^ bob_number) % 6 + 1")
	print("(" +str(alice_a) + " ^ " + str(bob_number) + ") % 6 + 1 = " + str(d))