# client.py  
import socket
import random
import copy
import math
import hashlib
import json
import string
import pprint


# create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
# get local machine name
host = socket.gethostname()                           

port = 9978

# connection to hostname on the port.
s.connect((host, port))           


####################### UTILITY FUNCTIONS ############################

def random_string_generator(size=10, chars=string.ascii_letters + string.digits + string.punctuation):
    return ''.join(random.choice(chars) for _ in range(size))

def power(b, e, m):
    #base case
    if (m==1):
        return 0
    #perform RSM
    result = 1
    #b = b%m
    while(e>0):
        if (e%2==1):
            result = ((result*b) % m)

        b = ((b*b)%m)
        e = e // 2


    return result

def modulo_inv(a, m) :
    m0 = m
    y = 0
    x = 1
 
    if (m == 1) :
        return 0
 
    while (a > 1) :
 
        # q is quotient
        q = a // m
 
        t = m
 
        # m is remainder now, process
        # same as Euclid's algo
        m = a % m
        a = t
        t = y
 
        # Update x and y
        y = x - q * y
        x = t
 
 
    # Make x positive
    if (x < 0) :
        x = x + m0
 
    return x


####################### KEY GENERATION ############################

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

        return json.dumps(final, indent =1);

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

        return json.dumps(final, indent =1);

    def verstatus_msg(self, status):
        final = copy.deepcopy(self.message);
        header = copy.deepcopy(self.header);

        header['opcode'] = 20;
        header['s_addr'] = 'server';
        header['d_addr'] = 'client';

        final['ver_status'] = status;

        return json.dumps(final, indent=1);


class KeyGenerator:
    '''
    Key generator class
    '''

    def rabin_miller(self, n):


        #Initialise q = n-1
        q = copy.deepcopy(n-1)

        #Initialise k where n-1 = 2^k * q
        k=0

        #Find k and q
        while(q%2==0 and q>0):
            q = q // 2
            k+=1

       # print ("q : ", q)
       # print ("k : ", k)

        #Select the random integer between [2, n-2]
        a = 2 + (random.getrandbits(20) % (n-1))

        #Do miller-rabin
        if (power(a, q, n)==1):
            return 1

        exp = copy.deepcopy(q)

        for i in range(0,k):
            if (power(a,exp, n)== n-1):
                return 1;
            exp = exp * 2

        return 0


    def generate_p(self):

        #Generate p via miller rabin algorithm

        while(1):
            p =  10000 + random.getrandbits(20)
           # print ("Trying p : ", p)
            #Set no. of times you want to run Miller-rabin to test primality. 10 is best.
            flag_rabin = 1
            t = 10

            while(t>0):
                #print (t)
                if (self.rabin_miller(p)==1):
                    t-=1
                    continue
                else:
                    flag_rabin = 0 
                    break
                #print (t)
                t-=1

           # print ("out of loop")
            if (flag_rabin == 1):
                break


        print ("Generated prime p :", p)
        return p

    def generate_prime_divisor(self, p):

        #Find q, the prime divisor of p-1
        #For this, eliminate multiples of 2 first.

        w = copy.deepcopy(p-1)
        '''

        # METHOD 1:

        while (1):
            
            if (w%2==0):
                w=w/2;
            else:
                break;

        gen = int(math.sqrt(w))
        q = 3

        while (gen <= int(math.sqrt(w)) ):
            if (w%gen == 0):
                q = copy.deepcopy(gen)
                break
            gen+=1

        print ("q: ", q)
        return q
        '''

        #METHOD 2:
        q=3
        while(1):
            q = random.randint(2,w)

            #Check divisibility
            if (w%q != 0 ):
                continue

            flag_rabin = 1
            t = 10

            while(t>0):
                #print (t)
                if (self.rabin_miller(q)==1):
                    t-=1
                    continue
                else:
                    flag_rabin = 0 
                    break
                #print (t)
                t-=1

           # print ("out of loop")
            if (flag_rabin == 1):
                break
        
        print ("q: ", q)
        return q
         



    def generate_alpha(self, p, q):

        g = 2 + (random.getrandbits(20)%(p-2))

        alpha = power(g , (p-1)//q , p)

        print ("Alpha = ", alpha)
        return alpha


    def compute_a_and_y(self, alpha, p, q):
        a = 1 + (random.getrandbits(20)%(q-1))

        y = power(alpha, a, p)

        print ("Private key a :", a)
        print ("Public key y : ", y)
        return a,y



####################### KEY SIGNATURE CLASS ############################

    
class KeySignature:
    '''
    Key Signature class
    '''

    def generate_k(self, q):
        k = 1 + (random.getrandbits(20)%(q-1))
        print ("Random secret integer k : ", k)
        return k


    def compute_r(self, alpha, k, p):

        r = power(alpha, k, p)
        print ("r is = ", r)

        return r


    def compute_hash(self, m, r, p):
        #concat message and r
        #md = ''.join(format(ord(x), 'b') for x in m)

        #concat_msg = md + str(int('{0:b}'.format(r) ,2))       #print ("concat_m: ", concat_m)

        #Get hash
        sha1 = hashlib.sha1()
        sha1.update(m.encode())
        sha1.update(str(r).encode())
        #sha1.update(str(concat_msg).encode())
        hashed_message = sha1.hexdigest()
        print ("Hash :", int(hashed_message, 16) % p)

        return int(hashed_message, 16) % p


    def compute_s(self, a, e, k, q):
        #print (a*int(e)+k)
        s = (((a*e) % q) + k%q) % q

        print("s : ", s)
        return s

    def compute_u(self, alpha, p, q):
        while(1):
            u = 1 + random.getrandbits(20)%(q)
            temp = power(alpha, u, p)

            #if (modulo_inv(temp,p) == False):
            #    continue
            #else:
            print ("u : ", u)
            return u




    def compute_r_dash(self, u, v, r, alpha, y, p, q):

        #v = 1 + random.getrandbits(20)%(q)

        temp = power(alpha, u, p)

        r_dash = ( (r%p) * (power(y,v,p)) * power(modulo_inv(alpha,p), u, p) ) % p

        print ("v : ", v)
        print ("r' : ", r_dash)
        return v, r_dash



def main():

    print ("\n-------------Key generation---------------\n")

    keygen = KeyGenerator()

    p = keygen.generate_p()
    q = keygen.generate_prime_divisor(p)
    alpha = keygen.generate_alpha(p, q)
    a, y = keygen.compute_a_and_y(alpha, p, q)

    pubkey = MessageStruct()
    PUBKEY = pubkey.pubkey_msg(p, q, alpha, y)
    s.send(PUBKEY.encode())


    print ("\n-------------Key signature----------------\n")

    keysign = KeySignature()

    k = keysign.generate_k(q)
    r = keysign.compute_r(alpha, k, p)
    #Get random message
    m = random_string_generator(size = 10)
    print ("m : ", m)
    e = keysign.compute_hash(m, r, p)
    
    s_sign = keysign.compute_s(a, e, k, q)    

    u = keysign.compute_u(alpha, p, q)
    v_list= [x for x in range(1, q)]

    while(len(v_list) > 0):
        v = random.choice(v_list)
        r_dash = keysign.compute_r_dash(u, v, r, alpha, y, p, q)
        e_dash = keysign.compute_hash(m, r_dash, p)
        print ("e' : ", e_dash)
        print ("e-v : ", e-v)

        if (e_dash != e-v and len(v_list)>1):
            v_list.remove(v)
            continue

        s_dash = s_sign- u
        print ("s' = s-u : ",s_sign - u )
        break

    #Send signature
    signature = MessageStruct()
    SIGNEDMSG = signature.signed_msg(m, e_dash, s_dash)
    s.send(SIGNEDMSG.encode())


    # Receive no more than 4096 bytes
    VERSTATUS_server = s.recv(4096)                                     
    VERSTATUS_server = json.loads(VERSTATUS_server)
    print ("\n-------------Verification received---------------\n")

    pprint.pprint (VERSTATUS_server)
    s.close()

   # print("The time got from the server is %s" % tm.decode('ascii'))

main()