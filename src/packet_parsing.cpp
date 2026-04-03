#include <pcap/pcap.h>
#include <time.h>
#include <cstring>
#include <iostream>
#include "packet_parsing.h"

PacketParser::PacketParser(std::string device) : device(device) {}

void PacketParser::packet_parser(const struct pcap_pkthdr *header, const u_char *packet){
    // TODO : Parse the packet and print the timestamp, source IP, destination IP, protocol, and packet length.
    struct tm *ltime;
    char timestr[16];
    time_t local_tv_sec;

    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr,sizeof timestr,"%H:%M:%S",ltime);

    printf("Timestamp: %s.%.6ld ",timestr,header->ts.tv_usec);
    printf("Packet Length: %d\n",header->len);
    for(int i =0 ; i < header->len; i++){
        printf("%02x ",packet[i]);
    }
    printf("\n\n");
}
