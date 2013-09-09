/************************************************************************
* Narseo Vallina-Rodriguez. University of Cambridge. 2013				*
* narseo@gmail.com                                                     	*
*************************************************************************/

#ifndef SPECTRUMUTILS_H
#define SPECTRUMUTILS_H

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>  // if using C99...  for C++ leave this out.
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>

#pragma pack(1)
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#pragma pack(pop)

#define UDP_HDR_LENGTH 8
#define EXIT_FAILURE -1
#define TRUE 1
#define IF_NAME "pdp0"
#define TUN_NAME "tun1"
#define LOG_TAG "SPC_PROX"

//#define htons(A) ((((unsigned short)(A) & 0xff00) >> 8) | (((unsigned short)(A) & 0x00ff) << 8))

/* to control the proc list
This seems to be a reasonable number
to reduce notably the number of /proc reads
*/
#define MAX_NUM_PROC 30

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28
#define TCPSYN_LEN 20

/*Specific ports to target*/
#define DNS_PORT 53
#define HTTP_PORT 80
#define HTTP_PORT_ALT 8080
#define HTTP_HEADER_READ_SIZE 700
#define MIN_HTTP_HEADER 64


/*Sleep time for starting process*/
#define INITIAL_SLEEP_TIME 45
/* Constants used for the port to process resolution*/
#define TCP 1
#define UDP 2

/*Used to have a max number of resolving threads running in parallel
#define NUM_THREADS 5
*/

//Used to define length of IP addr. Looks like android does not have it
#ifndef INET_ADDRSTRLEN
# define INET_ADDRSTRLEN 16
#endif /* INET_ADDRSTRLEN */

#define DEBUG 0

/* Vbes used for the logger */
#define LOGGER_BUFLEN 512
#define PORT 9930
#define SRV_IP "127.0.0.1"

typedef unsigned short u_int16;
typedef unsigned long u_int32;

struct inet_params {
        int local_port, rem_port, state, uid;
        union {
                struct sockaddr     sa;
                struct sockaddr_in  sin;
		#if ENABLE_FEATURE_IPV6
                struct sockaddr_in6 sin6;
		#endif
        } localaddr, remaddr;
        unsigned long rxq, txq, inode;
};

/************************************************************************
* struct: Pseudoheader
* 
* Used to compute TCP checksum. Check RFC 793
*************************************************************************/
#pragma pack(2)
typedef struct pseudoheader {
  u_int32_t src;
  u_int32_t dst;
  u_char zero;
  u_char protocol;
  u_int16_t tcplen;
} tcp_phdr_t;
#pragma pack(pop)

/************************************************************************
* struct: ThreadParam
* 
* used to run the port resolution thread
************************************************************************/
typedef struct {
  int transpProto;
  int localPort;
} ThreadParam;

/************************************************************************
* struct: PortCacheList
*
* used to accelerate the port resolution. Used to create a list ordered 
* by a timestamp. Recent short-lived connections are likely to be found
* first
************************************************************************/
typedef struct {
  int localPort;
  char *procName;
//  time_t timestamp;
  struct procInfo *next; 
} procInfo; 

char tun_name[IFNAMSIZ];
pthread_mutex_t mutex;
//Head of the linked list
procInfo *headListPtr;


/**************************************************************************
* function: tun_alloc
*
* Usage allocates or reconnects to a tun/tap device.
* The caller needs to reserve enough space in *dev. 
 **************************************************************************/
extern int tun_alloc(char *dev, int flags);


/************************************************************************
* Function: in_cksum()	
*
* Usage: CalculateS TCP checksum	
*************************************************************************/
extern unsigned short in_cksum(unsigned short *addr,int len);

/************************************************************************
* function: build_ipv4_addr
*
* Usage: Converts ip addr as string (hex) to sockaddr_in*
************************************************************************/
static void build_ipv4_addr(char* local_addr, struct sockaddr_in* localaddr);

/************************************************************************
* function: scan_inet_proc
*
* searches on /proc/net/tcp6 for a given *port*
* If found, it tries to identify the owner process
************************************************************************/
static int scan_inet_proc_line(struct inet_params *param, int port, char *line);


/************************************************************************
* function: tcp_do_one
* 
* usage: tracks tcp connections from /proc/net/tcp6
************************************************************************/
static int tcp_do_one(char *line, int port);

/************************************************************************
* function: xmalloc_fgets_internal
*
* usage: auxiliar function from busybox
************************************************************************/
static char *xmalloc_fgets_internal(FILE *file, const char *terminating_string, int chop_off, size_t *maxsz_p);



/************************************************************************
* function= xmalloc_fgets_str
* 
* Usage =  Read up to TERMINATING_STRING from FILE and return it,
* including terminating string.
* Non-terminated string can be returned if EOF is reached.
* Return NULL if EOF is reached immediately.  
* NOTE: Taken from busybox
************************************************************************/
extern char* xmalloc_fgets_str(FILE *file, const char *terminating_string);


/************************************************************************
* function: do_info
*
* Usage: Performs an action specified by proc on a given file 
* This is used to scan /proc/net/tcp6 or /proc/net/udp6 files 
************************************************************************/
static void do_info(const char *file, int localPort, int (*proc)(char *, int));


/************************************************************************
* function: portResolution
*
* Usage: Creates and starts a thread that will be responsible for 
* the port resolution. It first checks if it's already in the cache
* If not stored, it parses the proc filesystem to perform the search
* 
* It will communicate with the logger
* TODO: FINISH
************************************************************************/
extern void *portResolution (void *param);

/***********************************************************************
* function: safe_read
*
* usage: reads a file
************************************************************************/
extern size_t safe_read(int fd, void *buf, ssize_t count);


/************************************************************************
* function: full_read
*
* Read all of the supplied buffer from a file.
* This does multiple reads as necessary.
* Returns the amount read, or -1 on an error.
* A short read is returned on an end of file.
************************************************************************/
extern ssize_t full_read(int fd, void *buf, ssize_t len);


/************************************************************************
* function: read_close
* 
* usage: reads and closes a file
************************************************************************/
extern ssize_t read_close(int fd, void *buf, ssize_t size);

/************************************************************************
* function: open_read_close
*
* usage: opens, reads a closes a files (returned on *buf)
************************************************************************/
extern ssize_t open_read_close(const char *filename, void *buf, ssize_t size);

/************************************************************************
* function: ret_RANGE
*
* USAGE: Aux function from busybox
************************************************************************/
static unsigned long long ret_ERANGE(void);

/************************************************************************
* function: handle_errors
*
* USAGE: Aux function from busybox
************************************************************************/
static unsigned long long handle_errors(unsigned long long v, char **endp);


/************************************************************************
* function: bb_strtoull
*
* USAGE: Aux function from busybox
************************************************************************/
extern unsigned long long bb_strtoull(const char *arg, char **endp, int base);

/************************************************************************
* function: bb_strtoul
*
* USAGE: Aux function from busybox
************************************************************************/
extern unsigned long bb_strtoul(const char *arg, char **endp, int base);

/************************************************************************
* function: bb_strtol
*
* USAGE: Aux function from busybox
************************************************************************/
extern long bb_strtol(const char *arg, char **endp, int base);


/************************************************************************
* Function: extract_socket_inode
*
* Gets the socket_inode for a given fd
************************************************************************/
static long extract_socket_inode(const char *lname);



/************************************************************************
* function: xmalloc_readlink
*
* usage: used to read /proc/PID/fd/FD
* NOTE: This function returns a malloced char* that you will have to free
* yourself.
************************************************************************/
extern char* xmalloc_readlink(const char *path);


/************************************************************************
* Function: getProcessName
*
* Usage: iterates on the list and returns the process name for a given
* port
***********************************************************************/
extern char * searchTcpProcName(int port);

/************************************************************************
* Function addToList
*
* Usage: stores a new process info in the list. Nodes are added to the head
* and if max number of items is reached, they are removed from the tail.
* The oldest ports are less likely to be requested.
************************************************************************/
extern void addToList(char *cmd, int port);

/************************************************************************
* Function: scan_fd
* 
* Usage: Scans all the files under /fd for a given PID. 
* Obtains process name from /proc/PID/cmdline and reports to logger
* if found.
************************************************************************/
static void scan_fd(char *root, char *PID, int inodeTarget, int portNumber);

/************************************************************************
* Function: prg_cache_load
*
* Usage: Reads /proc/PID/fd/FD_ID looking for socket that corresponds 
* to a given inode
************************************************************************/
extern void prg_cache_load(char * root_dir, int proto, int port, int inode);

/************************************************************************
* Function: cksum																												*
* Computes IP CHECKSUM. In reality, does the same as the TCP one but 		*
* just in case...																												*
*************************************************************************/
extern uint16_t cksum (const void *_data, int len);

//TODO
/**************************************************************************
 * parseHTTPRequest: Parses an http request															  *
 *         returned.                                                      *
 **************************************************************************/
/*
int parseHTTPRequest(char *buf, int n){  
		printf("%s\n", buf);
}
*/

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
extern cread(int fd, char *buf, int n);

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
extern int cwrite(int fd, char *buf, int n);

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
extern int read_n(int fd, char *buf, int n);

/**************************************************************************
 * do_debug: prints debugging stuff
 **************************************************************************/
extern void do_debug(char *msg, ...);


/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
extern void my_err(char *msg, ...);



/**************************************************************************
* function: print_log
*
* usage: communicates with logger via local UDP socket															*
**************************************************************************/
extern void print_log(char *buf, size_t sbuf);

/**************************************************************************
* usage: kills process	
*
**************************************************************************/
extern void diep(char *s);


/**************************************************************************
* function: print_ip
*
* usage: prints ip in standard output.	   																		   	            *
**************************************************************************/
extern void print_ip(int ip);

#endif /* SPECTRUMUTILS_H */


