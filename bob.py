import socket,pickle,random
import rsa as r
from rsa.pkcs1 import VerificationError
from functions2 import *

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind((socket.gethostname(), 1234))
s.settimeout(10)
s.listen(2)
s,address = s.accept()


#gen_keys("Bob")


"""
Recive a hashed, signed commitment from Alice
"""
msg = b""

msg_recv = s.recv(BUFFER)
msg = msg+msg_recv



payload = pickle.loads(msg)
alice_comm = payload['comm']
alice_signed_comm = payload['signed_comm']

"""
Checks if the message is actually from Alice using her signature
"""

try:
	verification = verify_sign(alice_comm, 'Alice',alice_signed_comm)
	print("Message was signed with algorithm: "+verification)
except VerificationError:
	print("Verification failed!\nMessage not from Alice, breaking")
finally:
	pass


"""
Bob now sends his number to Alice 
"""

bob_number = random.getrandbits(3)
signed_b = sign_mess(bob_number,"Bob")
d = {
	"signed_mess": signed_b,
	"number":bob_number
	}
msg_send = pickle.dumps(d)

s.send(msg_send)


"""
Bob gets an opened commitment from Alice and verifies that she did not cheat
"""
msg = b""

msg_recv = s.recv(BUFFER)
msg = msg+msg_recv


payload = pickle.loads(msg)
alice_a = payload['alice_number']
alice_salt = payload['alice_salt']
assert(verify_comm(alice_a, alice_salt,alice_comm))

"""
Computing the number
"""

if verification:
	d = aXORb(str(alice_a),bob_number)
	print("Compute d = (alice_number ^ bob_number) % 6 + 1")
	print("(" +str(alice_a) + " ^ " + str(bob_number) + ") % 6 + 1 = " + str(d))