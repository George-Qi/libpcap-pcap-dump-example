#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define INTERFACE "en0"
#define FLTRSZ 120
#define MAXHOSTSZ 256
#define PCAP_SAVEFILE "./pcap_savefile.pcap"

extern char *inet_ntoa();


int
main(int argc, char **argv)
{
        pcap_t *p;               /* packet capture descriptor */
        struct pcap_stat ps;     /* packet statistics */
        pcap_dumper_t *pd;       /* pointer to the dump file */
        char filename[80];       /* name of savefile for dumping packet data */
        char errbuf[PCAP_ERRBUF_SIZE];  /* buffer to hold error text */
        int optimize = 1;        /* passed to pcap_compile to do optimization */
        int snaplen = 65535;        /* amount of data per packet  (http://www.tcpdump.org/manpages/pcap.3pcap.html) */
        int promisc = 0;         /* do not change mode; if in promiscuous */                 /* mode, stay in it, otherwise, do not */
        int to_ms = 5000;        /* timeout, in milliseconds */
        uint32_t net = 0;         /* network IP address */
        uint32_t mask = 0;        /* network address mask */
        char netstr[INET_ADDRSTRLEN];   /* dotted decimal form of address */
        char maskstr[INET_ADDRSTRLEN];  /* dotted decimal form of net mask */
        int linktype = 0;        /* data link type */

        /*
         * If there is a second argument (the name of the savefile), save it in
         * filename. Otherwise, use the default name.
         */
        strcpy(filename, PCAP_SAVEFILE);

        /*
         * Open the network device for packet capture. This must be called
         * before any packets can be captured on the network device.
         */
        if (!(p = pcap_open_live(INTERFACE, snaplen, promisc, to_ms, errbuf))) {
                fprintf(stderr, "Error opening interface %s: %s\n",
                        INTERFACE, errbuf);
                exit(2);
        }

        /*
         * Look up the network address and subnet mask for the network device
         * returned by pcap_lookupdev(). The network mask will be used later 
         * in the call to pcap_compile().
         */
        if (pcap_lookupnet(INTERFACE, &net, &mask, errbuf) < 0) {
                fprintf(stderr, "Error looking up network: %s\n", errbuf);
                exit(3);
        }

        /*
         * Create the filter and store it in the string called 'fltstr.'
         * Here, you want only incoming packets (destined for this host),
         * which use port 69 (tftp), and originate from a host on the
         * local network.
         */

        // /* First, get the hostname of the local system */
        // if (gethostname(lhost,sizeof(lhost)) < 0) {
        //         fprintf(stderr, "Error getting hostname.\n");
        //         exit(4);
        // }

        
        //  * Second, get the dotted decimal representation of the network address
        //  * and netmask. These will be used as part of the filter string.
         
        // inet_ntop(AF_INET, (char*) &net, netstr, sizeof netstr);
        // inet_ntop(AF_INET, (char*) &mask, maskstr, sizeof maskstr);

        // /* Next, put the filter expression into the fltstr string. */
        // sprintf(fltstr,"dst host %s and src net %s mask %s and udp port 69",
        //         lhost, netstr, maskstr);

        // strcpy(fltstr,"");

        /*
         * Open dump device for writing packet capture data. In this sample,
         * the data will be written to a savefile. The name of the file is
         * passed in as the filename string.
         */
        if ((pd = pcap_dump_open(p,filename)) == NULL) {
                fprintf(stderr,
                        "Error opening savefile \"%s\" for writing: %s\n",
                        filename, pcap_geterr(p));
                exit(7);
        }

      
        while(1){
                pcap_loop(p,0,&pcap_dump,(u_char *)pd);
        }      

        // /*
        //  * Get and print the link layer type for the packet capture device,
        //  * which is the network device selected for packet capture.
        //  */
        // if (!(linktype = pcap_datalink(p))) {
        //         fprintf(stderr,
        //                 "Error getting link layer type for interface %s",
        //                 INTERFACE);
        //         exit(9);
        // }
        // printf("The link layer type for packet capture device %s is: %d.\n",
        //         INTERFACE, linktype);

        
         /* Get the packet capture statistics associated with this packet
         * capture device. The values represent packet statistics from the time
         * pcap_open_live() was called up until this call.
         
        if (pcap_stats(p, &ps) != 0) {
                fprintf(stderr, "Error getting Packet Capture stats: %s\n",
                        pcap_geterr(p));
                exit(10);
        }*/

        // /* Print the statistics out */
        // printf("Packet Capture Statistics:\n");
        // printf("%d packets received by filter\n", ps.ps_recv);
        // printf("%d packets dropped by kernel\n", ps.ps_drop);

        /*
         * Close the savefile opened in pcap_dump_open().
         */
        pcap_dump_close(pd);
        /*
         * Close the packet capture device and free the memory used by the
         * packet capture descriptor.
         */     
        pcap_close(p);
}