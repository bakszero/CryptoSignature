// Client side program

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <openssl/sha.h>
//Important for client
#include <netdb.h>


#define MAX_SIZE 160
#define MAX_LEN 1024
#define PORT 8022



/* Header of a message */
typedef struct {
int opcode; /* opcode for a message */
int s_addr; /* source address */
int d_addr; /* destination address */
}Hdr;


/* Signature of a message m */
typedef struct {
long e;
char s[MAX_SIZE];
}Signature;

/*A general message */
typedef struct {
Hdr hdr; /* Header for a message */
long long int p; /* A large prime */
long long int q; /* A prime factor of (p-1)*/
long long int g; /* g = h (p−1)/q mod p, with 1 < h < (p − 1) and g > 1 */
long long int y; /* A public key generated by user */
char plaintext[MAX_LEN]; /* Contains a plaintext message*/
Signature sign; /* Contains the signature on a plaintext message*/
long long int ver_status; /* Successful or unsuccessful result in signature verification */
long long int dummy; /*dummy variable is used when necessary */
}Msg;



//Global array for holding primes
long int check[10000]={0};
long int primes[10000]={0};


//Set global public variables
long long int q = 29;
long long int alpha = 11;

//Set global int array holding values of q, alpha, Y_a
long long int arr[3]={0};

//Set global encoding
char encoding[67] = {' ','A','B','C','D','E','F','G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 
					 'O', 'P','Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ',','.', '?','0','1'
					 ,'2','3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
					 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
					 'w', 'x', 'y', 'z', '!'};     


//Modular exponentiation (b^e % m)
long long int power(long long int b, long long int e, long long int m)
{  
    //base case
    if (m==1)
        return 0;

    long long int result = 1;
    b = b %m ;
    while (e > 0)
    {
    	if (e %2)
    		result = ((result*b) % m);
    	e = e >> 1;
    	b = ((b*b)%m);
    }

    return result;
    
}

//Sieve function
void sieve()
{
    int i, j;
    
    check[0]=1;
    check[1]=1;

    for (i=3; i <= sqrt(10000); i++)
    {
        if (check[i]==0)
        {
            for (j= i*i; j < 10000 ; j=j+i )
            {
                check[j]= 1;
            }
        }
    }
}



//Rabin Miller check
int rabbin_miller(long long int n)
{
	//Initialise q = n-1
	long long int q =  n-1;

	//Initialise k where n-1 = 2^k * q
	long long int k = 0;

	//Find k and q
	while(q%2==0 && q>0)
	{
		q = q>>1;
		k+=1;
	}


	//Select the random integer between [2, n-2]
	long long int a = 2 + rand() % (n - 4);


	//Do miller-rabin
	if (power(a, q, n)==1)
		return 1;

	long long int j;
	long long int exp = q;
	for (j=0; j <= k-1 ; j++)
	{
		if (power(a,exp, n)== n-1)
			return 1;
		exp = exp * 2;
	}

	return 0;

}	



//Store primes
int prime_generator()
{
    sieve();
    int i;
    int  j= 0;
    for (int i= 0 ; i < 10000; i++)
    {
        if (check[i]==0)
        {
            primes[j]=i;
            j++;
            //printf("%ld\n", j );
        }

    }
    return j;
}

//Error function
void error(const char *msg)
{
    perror(msg);
    exit(1);
}
  

//Generalized caesar cipher encryption
long long int encrypt_cipher(long long int p, long long int k, long long int m)
{
	return ((p%m)+(k%m))%m;
}


//Generalized caesar cipher decryption
long long int decrypt_cipher(long long int c, long long int k, long long int m)
{
    return ((((c-k)%m) + m)%m);
}

//Finding index in array
int findIndex(char *array, int size, char target) 
{
    int i=0;
    while((i<size) && (array[i] != target))
    	i++;

    return (i<size) ? (i) : (-1);
}




//Generating alpha
long long int generate_alpha(long long int g, long long int temp_alpha, long long int p)
{
    
}
int main(int argc, char const *argv[])
{
    //Random
    srand(time(NULL));

    /***

    ------KEY GENERATION PHASE------


    ***/
    printf("--------Key generation-----------\n");

    //Generate p via miller rabin algorithm
    long long int p;
    while(1)
    {
		p = 10000 + rand();

	    //Set no. of times you want to run Miller-rabin to test primality. 10 is best.
	    long long int flag_rabin = 1;
	    long long int t = 10;
	    while (t--)
	    {
	    	if (rabbin_miller(p))
	    		continue;
	    	else
	    	{
	    		flag_rabin = 0;
	    		break;
	    	}
	    }

	    if (flag_rabin == 1)
	    	break;

	}
	printf("p  : %lld\n", p );


	//Find q, the prime divisor of p-1
	//For this, eliminate multiples of 2 first.

	long long int w = p-1;
	while (1)
	{
		if (w%2==0)
			w=w/2;
		else
			break;

	}
	long long int gen = 3;
	long long int q = 3;
	for (gen = sqrt(w); gen >=3 ; gen--)
	{
		if (w%gen==0)
		{
			q = gen;
			break;
		}
	}

	printf("q :  %lld\n", q);




    //Generate alpha
    long long int temp_alpha = (p-1)/q;
    long long int g = 2 + abs(rand()) % (p-1); 
    long long int alpha = power(g, temp_alpha, p);
    printf("Alpha: %lld\n",alpha );



    //Select a private key a, [1,q-1]
    long long int a = 1 + abs(rand()) % (q-1);
    printf("a : %lld\n", a);


    //Compute y
    long long int y_dig = power(alpha, a , p);
    printf("y : %lld\n", y_dig);


    //Declare the message
    Msg message;
    message.p = p;
    message.q = q;
    message.g = g;
    message.y = y_dig;



    /***

    ------KEY SIGNATURE PHASE------


    ***/

    printf("--------Key signature-----------\n");


    //Select random integer k
    long long int k_dig = 1 + abs(rand()) % (q);
    printf("k : %lld\n",k_dig );

    //Compute r
    long long int r = power(alpha, k_dig, p);
    printf("r : %lld\n", r );

    //Let user enter message
    printf("Enter the message you want to send...\n");

    char mssg_before_hash[1024];
    scanf("%s", &mssg_before_hash);

    //Generate the hash using SHA-1
    size_t length_of_message = sizeof(mssg_before_hash);
    char hash[1024];
    SHA1(mssg_before_hash, length_of_message, hash);

    printf("%s\n", hash );



























	//Get random integer X_a less than q, X_b less than q
	long long int X_a = (long long int) rand() % q;


    //Compute public function Y_a
    long long int Y_a  = power (alpha, X_a, q);


    //Set the global values
    arr[0] = Y_a;
    arr[1] = q;
    arr[2] = alpha;

    //printf("%lld %lld %lld %lld\n",q,alpha,X_a,Y_a );


    //Connection protocols
    //------------------------------------------------------------------

    struct sockaddr_in serv_addr;
    int sock = 0, valread;

    char *hello = "efeff";
    long long int buffer[3] = {0};

    struct hostent *server;


    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	    error("socket creation error.\n");


	bzero((char *) &serv_addr, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    //bcopy((char *)server->h_addr,(char *)&serv_addr.sin_addr.s_addr,server->h_length);
    serv_addr.sin_port = htons(PORT);

  
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		error("error connecting...");



    //------------------------------------------------------------------

	//Key exchange

	//Send key to B
    int n = write(sock , arr , sizeof(arr) );
    if (n< 0)
    	error("Error writing to socket.");


    //Receive key from B
    int x = read(sock, buffer, sizeof(buffer));
    if (x<0)
        error("Error reading from the client socket.");

    //printf("%s\n", buffer );
    //printf("Y_b = %lld\n", buffer[0]);
    //printf("q = %lld\n", buffer[1]);
    //printf("alpha = %lld\n", buffer[2]);

    long long int Y_b = buffer[0];
   //------------------------------------------------------------------

    //Generate secret key by User A
    long long int k = power(Y_b, X_a,q);
    printf("k = %lld\n", k);



    //------------------------------------------------------------------
    //Send ciphertext from A
    //Encryption of text

    char  * mssg = "BAKHTIYAR bakhtiyar ...,,,!!!";

    int len_mssg = strlen(mssg);
    //printf("%d\n", len_mssg );
    int int_mssg[len_mssg];
    char encrypt_mssg[len_mssg];

    int i = 0,j=0;

    //Encode
    for (i=0; i < len_mssg; i++)
    {
    	int_mssg[i] = findIndex(encoding, 67, mssg[i]);
    	//printf("%c - %d\n", mssg[i], int_mssg[i] );
    }

    //Encrypt
    for (j=0; j < len_mssg; j++)
    {	
    	//printf("%lld\n", );
    	encrypt_mssg[j] =  encoding[encrypt_cipher(int_mssg[j], k , 67)];
    	printf("%c", encrypt_mssg[j] );
    }

    //------------------------------------------------------------------

    //Send the encrypted text

    //Send the length first, so that we can track it.
    long long int len_arr[1]={len_mssg};
    //printf("size of encrypt_mssg %lld\n", len_arr[0] );
    int l= write(sock , len_arr, sizeof(len_arr));
    if (l< 0)
    	error("Error writing to socket.");
   
    l= write(sock , encrypt_mssg , sizeof(encrypt_mssg));
    if (l< 0)
    	error("Error writing to socket.");

    //------------------------------------------------------------------
    
    //Receive ciphertext from B
    
    int y;
    int recv_arr[1]={0};

    x = read(sock , recv_arr, sizeof(recv_arr));
    if (x<0)
        error("Error reading from the client socket.");

    //printf("X %lld\n", recv_arr[0] );

    char cipherb[recv_arr[0]];
    while((y = read(sock , cipherb, (size_t) recv_arr[0]))>0)
    {
        cipherb[y] = '\0';
        //printf("%s\n", cipher );
    }

    //printf("%s\n", cipher);

    //Decrypt the cipher
    //printf("strlen of ciphertext %d\n",strlen(cipherb) );
    char plain_cipher[strlen(cipherb)];
    for (j=0 ; j < strlen(cipherb); j++)
       {
        plain_cipher[j]= encoding[decrypt_cipher(findIndex(encoding, 67, cipherb[j]), k , 67)];
        printf("%c",plain_cipher[j] );
    }
	//shutdown(sock, 2);



    return 0;


}