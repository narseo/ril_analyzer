/*************************************************************************
* Narseo Vallina-Rodriguez. University of Cambridge. 2013				*
* narseo@gmail.com                                                     	*
*************************************************************************/

#include "spectrumutils.h"

/**************************************************************************
* function: tun_alloc
*
* Usage allocates or reconnects to a tun/tap device.
* The caller needs to reserve enough space in *dev. 
 **************************************************************************/
int tun_alloc(char *dev, int flags) {
	struct ifreq ifr;
	int fd, err;

	if( (fd = open("/dev/tun", O_RDWR)) < 0 ) {
		perror("Opening /dev/tun");
		return fd;
	}
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = flags;

	if (*dev) {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
		perror("ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}
	strcpy(dev, ifr.ifr_name);
	return fd;
}


/************************************************************************
* Function: in_cksum()	
*
* Usage: CalculateS TCP checksum	
*************************************************************************/
unsigned short in_cksum(unsigned short *addr,int len){
	register int sum = 0;
	u_short answer = 0;
	register u_short *w = addr;
	register int nleft = len;
    
	/*
	* The algorithm is simple, using a 32-bit accumulator (sum),
	* we add sequential 16-bit words to it, and at the end, fold back 
	* all the carry bits from the top 16 bits into the lower 16 bits. 
	*/
    	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum &0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16); /* add carry */
	answer = ~sum; /* truncate to 16 bits */
	return(answer);
} 

/************************************************************************
* function: build_ipv4_addr
*
* Usage: Converts ip addr as string (hex) to sockaddr_in*
************************************************************************/
static void build_ipv4_addr(char* local_addr, struct sockaddr_in* localaddr)
{
        sscanf(local_addr, "%X", &localaddr->sin_addr.s_addr);
        localaddr->sin_family = AF_INET;
}

/************************************************************************
* function: scan_inet_proc
*
* searches on /proc/net/tcp6 for a given *port*
* If found, it tries to identify the owner process
************************************************************************/
static int scan_inet_proc_line(struct inet_params *param, int port, char *line)
{
        int num;
        /* IPv6 /proc files use 32-char hex representation
         * of IPv6 addressd, followed by :PORT_IN_HEX
         */
        char local_addr[33], rem_addr[33]; /* 32 + 1 for NUL */

        num = sscanf(line,
                        "%*d: %32[0-9A-Fa-f]:%X "
                        "%32[0-9A-Fa-f]:%X %X "
                        "%lX:%lX %*X:%*X "
                        "%*X %d %*d %ld ",
                        local_addr, &param->local_port,
                        rem_addr, &param->rem_port, &param->state,
                        &param->txq, &param->rxq,
                        &param->uid, &param->inode);
        if (num < 9) {
                return 1; /* error */
        }
	//These two lines are not needed at the moment but they are kept just in case
        build_ipv4_addr(local_addr, &param->localaddr.sin);
        build_ipv4_addr(rem_addr, &param->remaddr.sin);

	if (port == param->local_port){
		//Target port has been found on /proc/net/tcp6 file. Now try to get the PID that owns it
		prg_cache_load("/proc/", TCP, param->local_port, param->inode);
	}
	return 0;
}


/************************************************************************
* function: tcp_do_one
* 
* usage: tracks tcp connections from /proc/net/tcp6
************************************************************************/
static int tcp_do_one(char *line, int port)
{    
        struct inet_params param;
        memset(&param, 0, sizeof(param));
        if (scan_inet_proc_line(&param, port, line))
                return 1;
        return 0;
}

/************************************************************************
* function: xmalloc_fgets_internal
*
* usage: auxiliar function from busybox
************************************************************************/
static char *xmalloc_fgets_internal(FILE *file, const char *terminating_string, int chop_off, size_t *maxsz_p)
{
        char *linebuf = NULL;
        const int term_length = strlen(terminating_string);
        int end_string_offset;
        size_t linebufsz = 0;
        size_t idx = 0;
        int ch;
        size_t maxsz = *maxsz_p;

        while (1) {
                ch = fgetc(file);
                if (ch == EOF) {
                        if (idx == 0)
                                return linebuf; /* NULL */
                        break;
                }
		
		if (idx >= linebufsz) {
                        linebufsz += 200;
                        linebuf = realloc(linebuf, linebufsz);
                        if (idx >= maxsz) {
                                linebuf[idx] = ch;
                                idx++;
                                break;
                        }
                }

                linebuf[idx] = ch;
                idx++;

                /* Check for terminating string */
                end_string_offset = idx - term_length;
                if (end_string_offset >= 0
                 && memcmp(&linebuf[end_string_offset], terminating_string, term_length) == 0
                ) {
                        if (chop_off)
                                idx -= term_length;
                        break;
                }
        }
        /* Grow/shrink *first*, then store NUL */
        linebuf = realloc(linebuf, idx + 1);
        linebuf[idx] = '\0';
        *maxsz_p = idx;
        return linebuf;
}



/************************************************************************
* function= xmalloc_fgets_str
* 
* Usage =  Read up to TERMINATING_STRING from FILE and return it,
* including terminating string.
* Non-terminated string can be returned if EOF is reached.
* Return NULL if EOF is reached immediately.  
* NOTE: Taken from busybox
************************************************************************/
char* xmalloc_fgets_str(FILE *file, const char *terminating_string)
{
        size_t maxsz = INT_MAX - 4095;
        return xmalloc_fgets_internal(file, terminating_string, 0, &maxsz);
}


/************************************************************************
* function: do_info
*
* Usage: Performs an action specified by proc on a given file 
* This is used to scan /proc/net/tcp6 or /proc/net/udp6 files 
************************************************************************/
static void do_info(const char *file, int localPort, int (*proc)(char *, int))
{
        int lnr;
        FILE *procinfo;
        char *buffer;

        /* _stdin is just to save "r" param */
        procinfo = fopen(file, "r");
        if (procinfo == NULL) {
                return;
        }
        lnr = 0;
        /* Why xmalloc_fgets_str? because it doesn't stop on NULs */
        while ((buffer = xmalloc_fgets_str(procinfo, "\n")) != NULL) {
                /* line 0 is skipped */
                if (lnr && proc(buffer, localPort))
                        printf("%s: bogus data on line %d", file, lnr + 1);
                lnr++;
                free(buffer);
        }
        fclose(procinfo);
}


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
void *portResolution (void *param){
	ThreadParam *mThreadParam;
	mThreadParam  = (ThreadParam *) param;

	// Otherwise read and parse /proc
	do_info("/proc/net/tcp6", mThreadParam->localPort, tcp_do_one);

	//TODO: No port resolution for UDP traffic. Stupid overhead

	pthread_exit(NULL); //Maybe here we can return something
	return 0;
}

/***********************************************************************
* function: safe_read
*
* usage: reads a file
************************************************************************/
size_t safe_read(int fd, void *buf, ssize_t count)
{
        ssize_t n;
        do {
                n = read(fd, buf, count);
        } while (n < 0 && errno == EINTR);
        return n;
}


/************************************************************************
* function: full_read
*
* Read all of the supplied buffer from a file.
* This does multiple reads as necessary.
* Returns the amount read, or -1 on an error.
* A short read is returned on an end of file.
************************************************************************/
ssize_t full_read(int fd, void *buf, ssize_t len)
{
        ssize_t cc;
        ssize_t total;
        total = 0;
        while (len) {
                cc = safe_read(fd, buf, len);

                if (cc < 0) {
                        if (total) {
                                /* we already have some! */
                                /* user can do another read to know the error code */
                                return total;
                        }
                        return cc; /* read() returns -1 on failure. */
                }
                if (cc == 0)
                        break;
                buf = ((char *)buf) + cc;
                total += cc;
                len -= cc;
        }
        return total;
}


/************************************************************************
* function: read_close
* 
* usage: reads and closes a file
************************************************************************/
ssize_t read_close(int fd, void *buf, ssize_t size)
{
        /*int e;*/
        size = full_read(fd, buf, size);
        /*e = errno;*/
        close(fd);
        /*errno = e;*/
        return size;
}

/************************************************************************
* function: open_read_close
*
* usage: opens, reads a closes a files (returned on *buf)
************************************************************************/
ssize_t open_read_close(const char *filename, void *buf, ssize_t size)
{
        int fd = open(filename, O_RDONLY);
        if (fd < 0)
                return fd;
        return read_close(fd, buf, size);
}

/************************************************************************
* function: ret_RANGE
*
* USAGE: Aux function from busybox
************************************************************************/
static unsigned long long ret_ERANGE(void)
{
        errno = ERANGE; /* this ain't as small as it looks (on glibc) */
        return ULLONG_MAX;
}

/************************************************************************
* function: handle_errors
*
* USAGE: Aux function from busybox
************************************************************************/
static unsigned long long handle_errors(unsigned long long v, char **endp)
{
        char next_ch = **endp;

        /* errno is already set to ERANGE by strtoXXX if value overflowed */
        if (next_ch) {
                /* "1234abcg" or out-of-range? */
                if (isalnum(next_ch) || errno)
                        return ret_ERANGE();
                /* good number, just suspicious terminator */
                errno = EINVAL;
        }
        return v;
}


/************************************************************************
* function: bb_strtoull
*
* USAGE: Aux function from busybox
************************************************************************/
unsigned long long bb_strtoull(const char *arg, char **endp, int base)
{
        unsigned long long v;
        char *endptr;

        if (!endp) endp = &endptr;
        *endp = (char*) arg;

        /* strtoul("  -4200000000") returns 94967296, errno 0 (!) */
        /* I don't think that this is right. Preventing this... */
        if (!isalnum(arg[0])) return ret_ERANGE();

        /* not 100% correct for lib func, but convenient for the caller */
        errno = 0;
        v = strtoull(arg, endp, base);
        return handle_errors(v, endp);
}

#if ULONG_MAX != ULLONG_MAX
/************************************************************************
* function: bb_strtoul
*
* USAGE: Aux function from busybox
************************************************************************/
unsigned long bb_strtoul(const char *arg, char **endp, int base)
{
        unsigned long v;
        char *endptr;

        if (!endp) endp = &endptr;
        *endp = (char*) arg;

        if (!isalnum(arg[0])) return ret_ERANGE();
        errno = 0;
        v = strtoul(arg, endp, base);
        return handle_errors(v, endp);
}

/************************************************************************
* function: bb_strtol
*
* USAGE: Aux function from busybox
************************************************************************/
long bb_strtol(const char *arg, char **endp, int base)
{
        long v;
        char *endptr;
        char first;

        if (!endp) endp = &endptr;
        *endp = (char*) arg;

        first = (arg[0] != '-' ? arg[0] : arg[1]);
        if (!isalnum(first)) return ret_ERANGE();

        errno = 0;
        v = strtol(arg, endp, base);
        return handle_errors(v, endp);
}
#endif


/************************************************************************
* Function: extract_socket_inode
*
* Gets the socket_inode for a given fd
************************************************************************/
static long extract_socket_inode(const char *lname)
{	
	long inode = -1;
        if (strncmp(lname, "socket:[", sizeof("socket:[")-1) == 0) {
                /* "socket:[12345]", extract the "12345" as inode */
                inode = bb_strtoul(lname + sizeof("socket:[")-1, (char**)&lname, 0);
                if (*lname != ']')
                        inode = -1;
        } else if (strncmp(lname, "[0000]:", sizeof("[0000]:")-1) == 0) {
                /* "[0000]:12345", extract the "12345" as inode */
                inode = bb_strtoul(lname + sizeof("[0000]:")-1, NULL, 0);
                if (errno) /* not NUL terminated? */
                        inode = -1;
        }
#if 0 /* bb_strtol returns all-ones bit pattern on ERANGE anyway */
        if (errno == ERANGE)
                inode = -1;
#endif
        return inode;
}



/************************************************************************
* function: xmalloc_readlink
*
* usage: used to read /proc/PID/fd/FD
* NOTE: This function returns a malloced char* that you will have to free
* yourself.
************************************************************************/
char* xmalloc_readlink(const char *path)
{
        enum { GROWBY = 80 }; /* how large we will grow strings by */
        char *buf = NULL;
        int bufsize = 0, readsize = 0;
        do {
                bufsize += GROWBY;
                buf = realloc(buf, bufsize);
                readsize = readlink(path, buf, bufsize);
                if (readsize == -1) {
                        free(buf);
                        return NULL;
                }
        } while (bufsize < readsize + 1);
        buf[readsize] = '\0';
        return buf;
}


/************************************************************************
* Function: getProcessName
*
* Usage: iterates on the list and returns the process name for a given
* port
***********************************************************************/
char * searchTcpProcName(int port){
	pthread_mutex_lock(&mutex);
	char * procName;
	procInfo *tmp= headListPtr;
	if (tmp == NULL){
		//Empty list. Nothing to search for
		pthread_mutex_unlock(&mutex);
		return NULL;
	}
	else{
		int numItems = 0;
		if (tmp->localPort == port){
			procName = malloc(strlen(tmp->procName) +1);
                	strcpy(procName, tmp->procName);	
			do_debug ("Port %d found!!!. Process = %s. Num items scanned= %d\n", port, procName, numItems); 
			pthread_mutex_unlock(&mutex);
			return procName;
		}
		while (tmp->next != NULL){
			tmp = tmp-> next;
			numItems++;
		        if (tmp->localPort == port){
        	                procName = malloc(strlen(tmp->procName) +1);
	                        strcpy(procName, tmp->procName);
                        	do_debug ("Port %d found!!!. Process = %s. Num items scanned= %d\n", port, procName, numItems);
                	        pthread_mutex_unlock(&mutex);
        	                return procName;
	                }
		}
	}
	pthread_mutex_unlock(&mutex);
	return NULL;
}

/************************************************************************
* Function addToList
*
* Usage: stores a new process info in the list. Nodes are added to the head
* and if max number of items is reached, they are removed from the tail.
* The oldest ports are less likely to be requested.
************************************************************************/
void addToList(char *cmd, int port){
	pthread_mutex_lock(&mutex);
        procInfo *tmp = headListPtr;	//Used to have a ref to the head
	procInfo *prev = headListPtr;	//Used to have a ref to the prev to last item and later remove it
	if (headListPtr == NULL){
		//Empty list
		headListPtr = (struct procInfo  *) malloc (sizeof (procInfo));
		headListPtr->localPort = port;
		headListPtr->procName = malloc(strlen(cmd) +1);
		strcpy(headListPtr->procName, cmd);
		headListPtr->next = NULL;
	}
	else{
		//There's something already stored. Add new node if wasn't added already
		int numItems = 0;
		if (headListPtr->localPort == port){
			//The port to be added now has been already added and it's the first one in the list
			do_debug("Iterate to next: %d. ProcCmd = %s - Port = %d. Port already stored. \n", numItems, headListPtr->procName, headListPtr->localPort);
                       	pthread_mutex_unlock(&mutex); 
                        return;
		}
		while (headListPtr ->next !=NULL){
			numItems++;
			prev = headListPtr;
			headListPtr = headListPtr-> next;
			do_debug("Iterate to next: %d. ProcCmd = %s - Port = %d\n", numItems, headListPtr->procName, headListPtr->localPort);
			if (headListPtr->localPort == port){
				//Port found. Already stored. Not including it
				headListPtr = tmp;
				pthread_mutex_unlock(&mutex);
				return;
			}
		}
		//Creating aux proc to be added at the beginning
		procInfo *aux = (struct procInfo *) malloc (sizeof(procInfo));
		aux->localPort = port;
		aux->procName = malloc(strlen(cmd) +1);
                strcpy(aux->procName, cmd);
		aux->next = tmp;		
		numItems++;		
		if (numItems > MAX_NUM_PROC){
			//Max Number of items allowed for the list reached. Removing the last one (in theory the oldest one)
			free(headListPtr);
			prev->next = NULL;
		}
		//The head points now to the node added at the beginning
		headListPtr = aux;
	}
	pthread_mutex_unlock(&mutex);
}

/************************************************************************
* Function: scan_fd
* 
* Usage: Scans all the files under /fd for a given PID. 
* Obtains process name from /proc/PID/cmdline and reports to logger
* if found.
************************************************************************/
static void scan_fd(char *root, char *PID, int inodeTarget, int portNumber) {
        char proc_pid_fd_root[sizeof("/proc/%u/fd/%u/")+sizeof(long)*3];
        char proc_pid_fname[sizeof("/proc/%u/cmdline") + sizeof(long)*3];
	char cmdline_buf[512]; //Stores process name when read
	int n, len_fd, len;
	long inode;
	DIR *dir;
	struct dirent *ent;
	dir = opendir(root);
	if (dir != NULL){
		while ((ent = readdir(dir))!=NULL){
			//Check if they are sockets
                        if (isdigit(ent->d_name[0])) {
                                len_fd = snprintf(proc_pid_fd_root, sizeof(proc_pid_fd_root), "/proc/%s/fd/%s", PID, ent->d_name);	
				char *linkname;
				linkname = xmalloc_readlink(proc_pid_fd_root);
				if (linkname != NULL) {
			                inode = extract_socket_inode(linkname);
                			free(linkname);
					if (inode==inodeTarget){	
						//Get process name. Read /proc/PID/cmdline
          					memset(cmdline_buf, 0, sizeof(cmdline_buf));
                                		len = snprintf(proc_pid_fname, sizeof(proc_pid_fname), "/proc/%s/cmdline", PID);
                                		do_debug("Reading cmdLine file: %s. (ROOT for PID/fd = %s. PID read by scan_fd = %s)\n", proc_pid_fname, proc_pid_fd_root, PID);
						n = open_read_close(proc_pid_fname, cmdline_buf, sizeof(cmdline_buf) - 1);
                                		if (n < 0){
                                        		my_err("Error getting command name for PID = %s\n", PID);
                                        		//continue;
                                		}
                                		cmdline_buf[n] = '\0';
						do_debug("***** %s = PID %s/PORT %d/INODE %d\n", cmdline_buf, PID, portNumber, inode); 
						addToList(cmdline_buf, portNumber);
						//Close directory as file was found. Then leave and no need to parse anything else
						closedir(dir);
						return; 
                                	}
				}
			}				
		}
		closedir(dir);
	}
}

/************************************************************************
* Function: prg_cache_load
*
* Usage: Reads /proc/PID/fd/FD_ID looking for socket that corresponds 
* to a given inode
************************************************************************/
void prg_cache_load(char * root_dir, int proto, int port, int inode)
{
	//Used to access the files
	char proc_pid_fd[sizeof("/proc/%u/fd/")+sizeof(long)*3];
        int len_fd;
        DIR *dir;
        struct dirent *ent;
        dir = opendir (root_dir);
        if (dir != NULL) {
                /* print all the files and directories within directory */
                while ((ent = readdir (dir)) != NULL) {
                        if (isdigit(ent->d_name[0])) {
        			//GET IF FD is a socket                        
				len_fd = snprintf(proc_pid_fd, sizeof(proc_pid_fd), "/proc/%s/fd/", ent->d_name);	
				scan_fd(proc_pid_fd, ent->d_name, inode, port);
                        }
                }
                closedir (dir);
        } else {
        /* could not open directory */
                perror ("");
                return; //EXIT_FAILURE;
        }
}


/************************************************************************
* Function: cksum																												*
* Computes IP CHECKSUM. In reality, does the same as the TCP one but 		*
* just in case...																												*
*************************************************************************/
uint16_t cksum (const void *_data, int len)
{
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


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
int cread(int fd, char *buf, int n){  
  int nread;
  
  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {
  int nread, left = n;
  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff
 **************************************************************************/
void do_debug(char *msg, ...){  
  va_list argp; 
  if(DEBUG){
    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
  }
}


/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {
  va_list argp;
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}



/**************************************************************************
* function: print_log
*
* usage: communicates with logger via local UDP socket															*
**************************************************************************/
void print_log(char *buf, size_t sbuf){

	struct sockaddr_in si_other;
	int s, slen=sizeof(si_other);
	if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1){
		do_debug("ERROR: UDP LOGGER socket");
	}
	memset((char *) &si_other, 0, sizeof(si_other));
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(PORT);
	if (inet_aton(SRV_IP, &si_other.sin_addr)==0) {
		do_debug("ERROR: UDP LOGGER inet_aton() failed\n");
		exit(1);
	}
	do_debug("Sending packet \n");
	if (sendto(s, buf, sbuf, 0, &si_other, slen)==-1){
		diep("sendto()");
	}
	close(s);
}

/**************************************************************************
* usage: kills process	
*
**************************************************************************/
void diep(char *s)
{
	perror(s);
	exit(1);
}


/**************************************************************************
* function: print_ip
*
* usage: prints ip in standard output.	   																		   	            *
**************************************************************************/
void print_ip(int ip){
	unsigned char bytes[4];
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	if(DEBUG) 
	  printf("IP %d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);
}

