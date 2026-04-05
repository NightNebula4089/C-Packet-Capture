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

    parse_Ethernetframe(packet, header->len);

    printf("\033[1;34mTimestamp: %s.%.6ld\033[0m ",timestr,header->ts.tv_usec);
    printf("\033[1;34mPacket Length: %d\033[0m\n",header->len);
    for(int i =0 ; i < header->len; i++){
        printf("%02x ",packet[i]);
    }
    printf("\n\n");
}


/**
 * Handles parsing of the ethernet frame which will allow further parsing of the IP/TCP/UDP headers.
 */
void PacketParser::parse_Ethernetframe(const u_char *packet, int packet_len){

    if(packet_len < 14) return;

    unsigned char* dst_mac = (unsigned char*)packet;
    unsigned char* src_mac = (unsigned char*)(packet + 6);
    unsigned short ether_type = ntohs(*(unsigned short*)(packet + 12));

    int payload_offset = 14; // Default(if no VLAN tag present)
    if(ether_type == 0x8100 || ether_type == 0x88A8){ // VLAN tagged frame

        if(packet_len < 18) return; 

        ether_type = ntohs(*(unsigned short*)(packet + 16)); // Update EtherType to the one after VLAN tag
        payload_offset += 4; // VLAN tag adds 4 bytes
    }

    switch(ether_type){
        case 0x0800: // IPv4
            // parse_IPheader(packet + payload_offset);
            std::cout << "\033[1;32mIPv4 packet detected.\033[0m\n" << std::endl;
            break;
        case 0x0806: // ARP
            std::cout << "\033[1;32mARP packet detected.\033[0m\n" << std::endl;
            break;
        case 0x86DD: // IPv6
            // parse_IPv6header(packet+payload_offset);
            std::cout << "\033[1;32mIPv6 packet detected.\033[0m\n" << std::endl;
            break;
        default : 
            std::cout << "\033[1;31mUnknown Ethernet Type:\033[0m " << std::hex << ether_type  << "\n" << std::endl;
    }

}
