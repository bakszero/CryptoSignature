// Server side C/C++ program to demonstrate Socket programming
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <time.h>

//Global
long long int q=0;
long long int alpha = 0;

//Define the port no.
#define PORT 8022

//Set global encoding
char encoding[67] = {' ','A','B','C','D','E','F','G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 
                     'O', 'P','Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ',','.', '?','0','1'
                     ,'2','3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
                     'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                     'w', 'x', 'y', 'z', '!'};     

 

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
    //Because %  and mod behave differently for negative numbers. Subtle but excellent!
    return ((((c-k)%m) + m)%m);
}


//Modular exponentiation
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

//Finding index in array
int findIndex(char *array, int size, char target) 
{
    int i=0;
    while((i<size) && (array[i] != target))
        i++;

    return (i<size) ? (i) : (-1);
}

//Main function for server-client communication
int main(int argc, char const *argv[])
{
    int server_fd;
    int new_socket;
    int valread;

    struct sockaddr_in server_address, client_address;
    int opt = 1;
    int addrlen = sizeof(server_address);
    int clilen = sizeof(client_address);

    //set the buffer for receiving from client
    long long int buffer[3] = {0};

    char *hello = "Hello from server";





    //CONNECTION SET_UP
    //------------------------------------------------------------------
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        error("socket failed to create.");


    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, (const char*)&opt, sizeof opt))
        error("Failed to bind to port.");

    bzero((char *) &server_address, addrlen);

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons( PORT );
      
    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *) &server_address, sizeof(server_address))==-1)
        error("Unable to bind to port.");

    //Listen for clients
    listen(server_fd, 5);

    
    if ((new_socket = accept(server_fd, (struct sockaddr *) &client_address, &clilen))==-1)
        error("Accept failure.");

    //bzero(buffer, 1024);


    //------------------------------------------------------------------


    //Key exchange

    //Receive key from A
   
    int x = read(new_socket , buffer, sizeof(buffer));
    if (x<0)
        error("Error reading from the client socket.");

    //printf("%s\n", buffer );
    //printf("Y_a = %lld\n", buffer[0]);
    //printf("q = %lld\n", buffer[1]);
    //printf("alpha = %lld\n", buffer[2]);


    //Send Y_b to B
    q = buffer[1];
    alpha = buffer[2];
    long long int Y_a = buffer[0];

    //Get random integer X_b less than q, X_b less than q
    srand(time(NULL));
    long long int X_b = (long long int) rand() % q + 1;

    //------------------------------------------------------------------

    //Compute public function Y_b
    long long int Y_b  = power (alpha, X_b, q);

    //Store in arr;
    long long int arr[3]={0};
    arr[0] = Y_b;
    arr[1] = q;
    arr[2] = alpha;

    //printf("%lld %lld %lld %lld\n",q,alpha,X_b,Y_b );

    //Send Y_b to client A
    int n = write(new_socket , arr , sizeof(arr));
    if (n< 0)
        error("Error writing to socket.");
    
    //------------------------------------------------------------------

    //Generate secret key by this User B
    long long int k = power(Y_a, X_b,q);
    printf("k = %lld\n", k);


    //------------------------------------------------------------------
    //Receive ciphertext from A
    
    int r;
    long long int len_arr[1];
    x = read(new_socket , len_arr, sizeof(len_arr));
    if (x<0)
        error("Error reading from the client socket.");

    int length_a = len_arr[0];
    //printf("length_a = %d\n", length_a);

    char cipher[length_a];
    r = read(new_socket , cipher,length_a);
    if (r <0)
        error("HEY.");



  
    //printf("%s\n", cipher);
    //Reset len_arr
    len_arr[0]=0;

    //Decrypt the cipher
    //printf("strlen of ciphertext %d\n",strlen(cipher) );

    
    char plain_cipher[length_a];
    int j;
    for (j=0 ; j < strlen(cipher); j++)
     {
        plain_cipher[j]= encoding[decrypt_cipher(findIndex(encoding, 67, cipher[j]), k , 67)];
        printf("%c", plain_cipher[j]);
    }
    
    //printf("%s", plain_cipher);


    //------------------------------------------------------------------

    //Send ciphertext from B
    
    //Encryption of text
    
    char * mssg = "Meet me after the new year party at 10 P.M. night at IIIT felicity ground.";

    int len_mssg = strlen(mssg);
    int int_mssg[len_mssg];
    
    char encrypt_mssg[len_mssg];

    int i;
    //Encode
    for (i=0; i < len_mssg; i++)
    {
        int_mssg[i] = findIndex(encoding, 67, mssg[i]);
        //printf("%c", mssg[i] );
    }

    //Encrypt
    for (j=0; j < len_mssg; j++)
    {   
        //printf("%lld\n", );
        encrypt_mssg[j] =  encoding[encrypt_cipher(int_mssg[j], k , 67)];
        //printf("%c", encrypt_mssg[j] );
    }

    //------------------------------------------------------------------

    //Send the encrypted text
   // int len_arr[1]={sizeof(encrypt_mssg)};
    //Reset len_arr[0]
    len_arr[0]=sizeof(encrypt_mssg);
    int l= write(new_socket , len_arr, sizeof(len_arr));
    if (l< 0)
        error("Error writing to socket.");
    
    //printf("%s\n", encrypt_mssg );
    n = write(new_socket , encrypt_mssg , len_arr[0]);
    if (n< 0)
        error("Error writing to socket.");
    
    //shutdown(new_socket,2);
    //shutdown(server_fd,2);
    
    return 0;
}