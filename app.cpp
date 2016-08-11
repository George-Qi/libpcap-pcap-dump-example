#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <iostream>

#define INTERFACE "en0"
#define PCAP_SAVEFILE "./pcap_savefile.pcap"

extern char *inet_ntoa();

int start_dump(){
        pcap_t *p;               /* packet capture descriptor */
        struct pcap_stat ps;     /* packet statistics */
        pcap_dumper_t *pd;       /* pointer to the dump file */
        char filename[80];       /* name of savefile for dumping packet data */
        char errbuf[PCAP_ERRBUF_SIZE];  /* buffer to hold error text */
        int snaplen = 65535;        /* amount of data per packet  (http://www.tcpdump.org/manpages/pcap.3pcap.html) */
        int promisc = 0;         /* do not change mode; if in promiscuous */                 /* mode, stay in it, otherwise, do not */
        int to_ms = 5000;        /* timeout, in milliseconds */
        uint32_t net = 0;         /* network IP address */
        uint32_t mask = 0;        /* network address mask */
        char netstr[INET_ADDRSTRLEN];   /* dotted decimal form of address */
        char maskstr[INET_ADDRSTRLEN];  /* dotted decimal form of net mask */
        int linktype = 0;        /* data link type */

        strcpy(filename, PCAP_SAVEFILE);

        if (!(p = pcap_open_live(INTERFACE, snaplen, promisc, to_ms, errbuf))) {
                fprintf(stderr, "Error opening interface %s: %s\n",
                        INTERFACE, errbuf);
                return 2;
        }

        if (pcap_lookupnet(INTERFACE, &net, &mask, errbuf) < 0) {
                fprintf(stderr, "Error looking up network: %s\n", errbuf);
                return 3;
        }

        if ((pd = pcap_dump_open(p,filename)) == NULL) {
                fprintf(stderr,
                        "Error opening savefile \"%s\" for writing: %s\n",
                        filename, pcap_geterr(p));
                return 7;
        }

        while(1){
                pcap_loop(p,0,&pcap_dump,(u_char *)pd);
        }      

        pcap_dump_close(pd);  
        pcap_close(p); 
}


int main(int argc, char **argv) {
        std::cout << start_dump();
}