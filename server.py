# server.py 
import socket                                         
import time
import json
import hashlib
import copy
import pprint
# create a socket object
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

# get local machine name
host = socket.gethostname()                           

port = 9978
serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# bind to the port
serversocket.bind((host, port))                                  

# queue up to 5 requests
serversocket.listen(5)  

def power(b, e, m):
    #base case
    if (m==1):
        return 0
    #perform RSM
    result = 1
    b = b%m
    while(e>0):
        if (e%2==1):
            result = ((result*b) % m)
        e = e // 2
        b = ((b*b)%m)

    return result

def modulo_inv(a, n):

    dividend = copy.deepcopy(n);
    divisor = copy.deepcopy(a);
    rem = -1;
    step = 0;

    p=[]
    q=[]

    while(1):
        r = dividend % divisor
        if r != 0:
            rem = copy.deepcopy(r)
            q.append(int(dividend) // int(divisor))

            dividend = copy.deepcopy(divisor)
            divisor = copy.deepcopy(r)

            if step == 0:
                p.append(0)
            elif step == 1:
                p.append(1)
            else:
                p.append(p[step-2] + ((-p[step-1]*q[step-2]) % n))
        else:
            if rem != 1:
                return False
            else:
                p.append(p[step-2] + ((-p[step-1]*q[step-2]) % n))
                step += 1
                p.append(p[step-2] + ((-p[step-1]*q[step-2]) % n))

                return p[-1]

        step += 1        

class MessageStruct():

    def __init__(self):

        self.header = {
            'opcode' : -1,
            's_addr' : '',
            'd_addr' : ''
        };

        self.signature = {
            'e' : -1,
            's' : ''
        };

        self.message = {
            'hdr' : -1,
            'p' : -1,
            'q' : -1,
            'alpha' : -1,
            'g' : -1,
            'y' : -1,
            'plaintext' : -1,
            'sign_e' : -1,
            'sign_s' : -1,
            'ver_status' : -1,
            'dummy' : -1,
        };

    def pubkey_msg(self, p, q, alpha, y):
        final = copy.deepcopy(self.message);
        header = copy.deepcopy(self.header);

        header['opcode'] = 10;
        header['s_addr'] = 'client';
        header['d_addr'] = 'server';

        final['hdr'] = header;
        final['p'] = p;
        final['q'] = q;
        final['alpha'] = alpha;
        final['y'] = y;

        return json.dumps(final);

    def signed_msg(self, m, e, s):
        final = copy.deepcopy(self.message);
        header = copy.deepcopy(self.header);

        header['opcode'] = 20;
        header['s_addr'] = 'client';
        header['d_addr'] = 'server';

        final['hdr'] = header;
        final['plaintext'] = m;
        final['sign_e'] = e;
        final['sign_s'] = s;

        return json.dumps(final);

    def verstatus_msg(self, status):
        final = copy.deepcopy(self.message);
        header = copy.deepcopy(self.header);

        header['opcode'] = 20;
        header['s_addr'] = 'server';
        header['d_addr'] = 'client';

        final['ver_status'] = status;

        return json.dumps(final);


class SigVerifier:
    '''
    Verifies signature
    '''

    def compute_r_star(self, alpha, s_dash, y, e_dash, p):

        temp_1 = power(y, e_dash, p)

        temp_2 = power(alpha, s_dash, p)

        r_star = ( modulo_inv(temp_1,p) * temp_2 ) % p

        print (" r star is : ", r_star)
        return r_star 


    def compute_hash(self, m, r_star):
        sha1 = hashlib.sha1()
        sha1.update(m.encode())
        sha1.update(str(r_star).encode())
        hashed_message = sha1.hexdigest()
        print ("Hash :", int(hashed_message, 16))

        return int(hashed_message, 16)



        



'''
while True:
    # establish a connection
    clientsocket,addr = serversocket.accept()      

    print("Got a connection from %s" % str(addr))
    currentTime = time.ctime(time.time()) + "\r\n"
    clientsocket.send(currentTime.encode('ascii'))
    clientsocket.close()
'''
def main():

    clientsocket,addr = serversocket.accept()      

    print("Got a connection from %s" % str(addr))
    #currentTime = time.ctime(time.time()) + "\r\n"
    #clientsocket.send(currentTime.encode('ascii'))

    #Receive public key from client
    PUBKEY_client = clientsocket.recv(4096)
    PUBKEY_client = json.loads(PUBKEY_client)
    print ("\n-------------Public Key received---------------\n")

    pprint.pprint (PUBKEY_client)


    #Receive signature from the client
    SIGNEDMSG_client = clientsocket.recv(4096)
    SIGNEDMSG_client = json.loads(SIGNEDMSG_client)
    print ("\n-------------Signed message received---------------\n")

    pprint.pprint (SIGNEDMSG_client)

    print ("\n-------------Verification key---------------\n")

    alpha_server = PUBKEY_client['alpha']
    y_server = PUBKEY_client['y']
    p_server = PUBKEY_client['p']
    q_server = PUBKEY_client['q']

    s_dash_server = SIGNEDMSG_client['sign_s']
    e_dash_server = SIGNEDMSG_client['sign_e']

    message = SIGNEDMSG_client['plaintext']


    #Verify
    verifier = SigVerifier()
    r_star = verifier.compute_r_star(alpha_server, s_dash_server, y_server, e_dash_server, p_server )
    hash_val = verifier.compute_hash(message, r_star)

    print ("e_dash : ", e_dash_server)

    #Send verification status to client
    verstatus = MessageStruct()
    VERSTATUS = verstatus.verstatus_msg(int( hash_val == e_dash_server))
    clientsocket.send(VERSTATUS.encode('utf-8'))

    clientsocket.close()

main()