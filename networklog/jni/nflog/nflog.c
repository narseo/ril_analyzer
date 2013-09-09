/* (C) 2012 Pragmatic Software
   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/endian.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <errno.h>

#ifndef aligned_be64
#define aligned_be64 u_int64_t __attribute__((aligned(8)))
#endif

#include <linux/netfilter/nfnetlink_log.h>

char *netlog_if_indextoname (unsigned int ifindex, char *ifname);
void free_net_devices(void);
void cleanup(void);

#define MAX_NETDEVICES 32
static char *devices[MAX_NETDEVICES] = {0};

static inline void *nla_data(const struct nlattr *nla) {
    return (char *) nla + NLA_HDRLEN;
}
 
/* Structure used to swap the bytes in a 64-bit unsigned long long. */
union byteswap_64_u {
    unsigned long long a;
    uint32_t b[2];
};

/* Function to byteswap big endian 64bit unsigned integers
 * back to little endian host order on little endian machines. 
 * As above, on big endian machines this will be a null macro.
 * The macro ntohll() is defined in byteorder64.h, and if needed,
 * refers to _ntohll() here.
 *
 * Source: http://www.opensource.apple.com/source/CyrusIMAP/CyrusIMAP-187/cyrus_imap/lib/byteorder64.c?txt
 */
unsigned long long ntohll(unsigned long long x)
{
    union byteswap_64_u u1;
    union byteswap_64_u u2;
 
    u1.a = x;
 
    u2.b[1] = ntohl(u1.b[0]);
    u2.b[0] = ntohl(u1.b[1]);
 
    return u2.a;
}

unsigned long long htonll(unsigned long long x)
{
    union byteswap_64_u u1;
    union byteswap_64_u u2;

    u1.a = x;

    u2.b[0] = htonl(u1.b[1]);
    u2.b[1] = htonl(u1.b[0]);

    return u2.a;
}




static int parse_attr_cb(const struct nlattr *attr, void *data)
{
    const struct nlattr **tb = data;
    int type = mnl_attr_get_type(attr);

    /* skip unsupported attribute in user-space */
    if (mnl_attr_type_valid(attr, NFULA_MAX) < 0)
        return MNL_CB_OK;

    switch(type) {
        case NFULA_MARK:
        case NFULA_IFINDEX_INDEV:
        case NFULA_IFINDEX_OUTDEV:
        case NFULA_IFINDEX_PHYSINDEV:
        case NFULA_IFINDEX_PHYSOUTDEV:
            if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
                perror("mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            break;
        case NFULA_TIMESTAMP:
            if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
                        sizeof(struct nfulnl_msg_packet_timestamp)) < 0) {
                perror("mnl_attr_validate");
                //Narseo
                printf("Something weirdo\n");
                return MNL_CB_ERROR;
            }

            break;
        case NFULA_HWADDR:
            if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
                        sizeof(struct nfulnl_msg_packet_hw)) < 0) {
                perror("mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            break;
        case NFULA_PREFIX:
            if (mnl_attr_validate(attr, MNL_TYPE_NUL_STRING) < 0) {
                perror("mnl_attr_validate");
                return MNL_CB_ERROR;
            }
            break;
        case NFULA_PAYLOAD:
            break;
    }
    tb[type] = attr;
    return MNL_CB_OK;
}

char *netlog_if_indextoname (unsigned int ifindex, char *ifname)
{
    /* We may be able to do the conversion directly, rather than searching a
     *      list.  This ioctl is not present in kernels before version 2.1.50.  */
    struct ifreq ifr;
    int fd;
    int status;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0)
        return NULL;

    ifr.ifr_ifindex = ifindex;
    status = ioctl (fd, SIOCGIFNAME, &ifr);

    close (fd);

    if (status  < 0)
    {
        if (errno == ENODEV)
            /* POSIX requires ENXIO.  */
            errno = ENXIO;

        return NULL;
    }
    else
        return strncpy (ifname, ifr.ifr_name, IFNAMSIZ);
}

static inline char *get_net_device_name_by_index(int ifindex) {
    if(ifindex < 0 || ifindex > MAX_NETDEVICES - 1) {
        return NULL;
    }

    if(!devices[ifindex]) {
        devices[ifindex] = malloc(IFNAMSIZ);
        if(!devices[ifindex]) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }

        netlog_if_indextoname(ifindex, devices[ifindex]);
        if(!devices[ifindex]) {
            perror("if_indextoname");
            exit(EXIT_FAILURE);
        }
    }

    return devices[ifindex];
}

void free_net_devices(void) {
    int i;
    for(i = 0; i < MAX_NETDEVICES - 1; i++) {
        if(devices[i]) {
            free (devices[i]);
        }
    }
}

static int log_cb(const struct nlmsghdr *nlh, void *data)
{
    struct nlattr *tb[NFULA_MAX+1] = {};

    //Narseo: TIMESTAMPS.
    //netlink does not provide timestamp and pid
    //for incoming packets. 
    //To avoid any error in post-processing, I just add two timestamps
    //1) timeval tv is the one provided by netlink
    //2) timeval tv_processing is the time when the packet is being sent for processing
    //here
    //For incoming packets, they should be the same
    //In the analysis, we might realize that 
    //one of them is redundant. It's included as a preventive measure (i.e. just in case :))
    mnl_attr_parse(nlh, sizeof(struct nfgenmsg), parse_attr_cb, tb);
    struct timeval tv; //time for logging  
    struct timeval tv_processing; //time when the packet has been sent for processing
    gettimeofday(&tv, NULL); //Would be later updated if the it's an outgoing packet
    gettimeofday(&tv_processing, NULL);

    

    if (tb[NFULA_PREFIX]) {
        const char *prefix = mnl_attr_get_str(tb[NFULA_PREFIX]);
        printf("%s ", prefix);
    }

    if (tb[NFULA_TIMESTAMP]){
        //nflink has a timestamp for the packet
        struct nfulnl_msg_packet_timestamp *timestamp = mnl_attr_get_str(tb[NFULA_TIMESTAMP]);
        // nla_data(attr);

		tv.tv_sec = ntohll(timestamp->sec);
		tv.tv_usec = ntohll(timestamp->usec);
    }
    if (tb[NFULA_IFINDEX_INDEV]) {
        uint32_t indev = ntohl(mnl_attr_get_u32(tb[NFULA_IFINDEX_INDEV]));
        char *instr = get_net_device_name_by_index(indev);
        printf("IN=%s ", instr ? instr : "");
    } else {
        printf("IN= ");
    }

    if (tb[NFULA_IFINDEX_OUTDEV]) {
        uint32_t outdev = ntohl(mnl_attr_get_u32(tb[NFULA_IFINDEX_OUTDEV]));
        char *outstr = get_net_device_name_by_index(outdev);
        printf("OUT=%s ", outstr ? outstr : "");
    } else {
        printf("OUT= ");
    }

    if (tb[NFULA_PAYLOAD]) {
        struct iphdr *iph = (struct iphdr *) mnl_attr_get_payload(tb[NFULA_PAYLOAD]);

        printf("SRC=%u.%u.%u.%u DST=%u.%u.%u.%u TIME=%ld.%ld TIME_PROC=%ld.%ld ",
                ((unsigned char *)&iph->saddr)[0],
                ((unsigned char *)&iph->saddr)[1],
                ((unsigned char *)&iph->saddr)[2],
                ((unsigned char *)&iph->saddr)[3],
                ((unsigned char *)&iph->daddr)[0],
                ((unsigned char *)&iph->daddr)[1],
                ((unsigned char *)&iph->daddr)[2],
                ((unsigned char *)&iph->daddr)[3],
                tv.tv_sec, tv.tv_usec,
                tv_processing.tv_sec, tv_processing.tv_usec);

        printf("LEN=%u ", ntohs(iph->tot_len));

        switch(iph->protocol) 
        {
            case IPPROTO_TCP: 
                {
                    struct tcphdr *th = (struct tcphdr *) ((__u32 *) iph + iph->ihl);
                    //TODO: That seems to be the place to capture the rest of
                    //the stuff
                    //
                    //
                    //
                    printf("PROTO=TCP SPT=%u DPT=%u SQNUM=%u ACKSEQ=%u WIN=%u RES=%u DOFF=%u FIN=%u SYN=%u RST=%u PSH=%u ACK=%u URG=%u ECE=%u CWR=%u ",
                      ntohs(th->source), ntohs(th->dest),ntohs(th->seq), 
                      ntohs(th->ack_seq), ntohs(th->window), th->res1, th->doff, 
                      th->fin, th->syn, th->rst, th->psh, th->ack, th->urg,
                      th->ece, th->cwr);
                    break;
                }
            case IPPROTO_UDP:
                {
                    struct udphdr *uh = (struct udphdr *) ((__u32 *) iph + iph->ihl);
                    printf("PROTO=UDP SPT=%u DPT=%u LEN=%u ",
                            ntohs(uh->source), ntohs(uh->dest), ntohs(uh->len));
                    break;
                }
            case IPPROTO_ICMP:
                {
                    struct icmphdr *ich = (struct icmphdr *) ((__u32 *) iph + iph->ihl);
                    printf("PROTO=ICMP TYPE=%u CODE=%u ", 
                        ich->type, ich->code);
                    break;
                }
            default: 
                {
                    printf("PROTO=%u ", iph->protocol);
                }
        }
    }

    if (tb[NFULA_UID]) {
        uint32_t uid = ntohl(mnl_attr_get_u32(tb[NFULA_UID]));
        printf("UID=%u ", uid);
    }

    puts("");

    return MNL_CB_OK;
}

    static struct nlmsghdr *
nflog_build_cfg_pf_request(char *buf, uint8_t command)
{
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type	= (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
    nlh->nlmsg_flags = NLM_F_REQUEST;

    struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
    nfg->nfgen_family = AF_INET;
    nfg->version = NFNETLINK_V0;

    struct nfulnl_msg_config_cmd cmd = {
        .command = command,
    };
    mnl_attr_put(nlh, NFULA_CFG_CMD, sizeof(cmd), &cmd);

    return nlh;
}

    static struct nlmsghdr *
nflog_build_cfg_request(char *buf, uint8_t command, int qnum)
{
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type	= (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
    nlh->nlmsg_flags = NLM_F_REQUEST;

    struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
    nfg->nfgen_family = AF_INET;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(qnum);

    struct nfulnl_msg_config_cmd cmd = {
        .command = command,
    };
    mnl_attr_put(nlh, NFULA_CFG_CMD, sizeof(cmd), &cmd);

    return nlh;
}

    static struct nlmsghdr *
nflog_build_cfg_params(char *buf, uint8_t mode, int range, int qnum)
{
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type	= (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
    nlh->nlmsg_flags = NLM_F_REQUEST;

    struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(qnum);

    struct nfulnl_msg_config_mode params = {
        .copy_range = htonl(range),
        .copy_mode = mode,
    };
    mnl_attr_put(nlh, NFULA_CFG_MODE, sizeof(params), &params);

    return nlh;
}

struct mnl_socket *nl = 0;

void cleanup(void) {
  if(nl != 0)
    mnl_socket_close(nl);
  free_net_devices();
}

int main(int argc, char *argv[])
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    int ret;
    unsigned int portid, qnum;

    atexit(cleanup);

    if (argc != 2) {
        printf("Usage: %s [queue_num]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    qnum = atoi(argv[1]);

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        perror("mnl_socket_open");
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        exit(EXIT_FAILURE);
    }
    portid = mnl_socket_get_portid(nl);

    nlh = nflog_build_cfg_pf_request(buf, NFULNL_CFG_CMD_PF_UNBIND);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }

    nlh = nflog_build_cfg_pf_request(buf, NFULNL_CFG_CMD_PF_BIND);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }

    nlh = nflog_build_cfg_request(buf, NFULNL_CFG_CMD_BIND, qnum);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }

    nlh = nflog_build_cfg_params(buf, NFULNL_COPY_PACKET, 0xFFFF, qnum);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }

    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    if (ret == -1) {
        if(errno == ENOSPC || errno == ENOBUFS)  {
          /* ignore these (hopefully) recoverable errors */
        } else {
          perror("mnl_socket_recvfrom");
          exit(EXIT_FAILURE);
        }
    }
    
    while (1) {
      if (ret == -1) {
        /* reset ret and skip mnl_cb_run if previous recvfrom had an error */
        ret = 0;
      } else {
          
        //gettimeofday(&tv, NULL);
        //double timems = (double) tv.tv_sec + (double) 1e-6 * tv.tv_usec; 

        ret = mnl_cb_run(buf, ret, 0, portid, log_cb, NULL);
        if (ret < 0) {
          perror("mnl_cb_run");
          exit(EXIT_FAILURE);
        }
      }

      ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
      if (ret == -1) {
        if (errno == ENOSPC || errno == ENOBUFS) {
          /* ignore these (hopefully) recoverable errors */
          continue;
        } else {
          perror("mnl_socket_recvfrom");
          exit(EXIT_FAILURE);
        }
      }
    }

    return 0;
}
