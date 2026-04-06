#include <pcap/pcap.h>
#include <time.h>
#include <cstring>
#include <iostream>
#include "packet_parsing.h"

PacketParser::PacketParser(std::string device) : device(device) {}

void PacketParser::packet_parser(const struct pcap_pkthdr *header, const u_char *packet){
    // TODO : Parse the packet and print the timestamp, source MAC, destination MAC, protocol, and packet length.
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
    int payload_len = packet_len - (payload_offset); // Default(if no VLAN tag present)
    if(ether_type == 0x8100 || ether_type == 0x88A8){ // VLAN tagged frame

        if(packet_len < 18) return; 

        ether_type = ntohs(*(unsigned short*)(packet + 16)); // Update EtherType to the one after VLAN tag
        payload_len = payload_len - 4; // VLAN tag takes away 4 bytes
        payload_offset += 4; // VLAN tag adds 4 bytes
    }

    switch(ether_type){
        case 0x0800: // IPv4
            std::cout << "\033[1;32mIPv4 packet detected.\033[0m\n" << std::endl;
            std::cout << "\033[1;31m Mac Src :  " << std::hex << *(unsigned int*)src_mac << "\033[0m\n" << std::endl;
            std::cout << "\033[1;31m Mac Dst :  " << std::hex << *(unsigned int*)dst_mac << "\033[0m\n" << std::endl;
            parse_Ipv4(packet + payload_offset, payload_len);   
            break;
        case 0x0806: // ARP
            std::cout << "\033[1;32mARP packet detected.\033[0m\n" << std::endl;
            std::cout << "\033[1;31m Mac Src :  " << std::hex << *(unsigned int*)src_mac << "\033[0m\n" << std::endl;
            std::cout << "\033[1;31m Mac Dst :  " << std::hex << *(unsigned int*)dst_mac << "\033[0m\n" << std::endl;
            break;
        case 0x86DD: // IPv6
            std::cout << "\033[1;32mIPv6 packet detected.\033[0m\n" << std::endl;
            std::cout << "\033[1;31m Mac Src :  " << std::hex << *(unsigned int*)src_mac << "\033[0m\n" << std::endl;
            std::cout << "\033[1;31m Mac Dst :  " << std::hex << *(unsigned int*)dst_mac << "\033[0m\n" << std::endl;
            // parse_Ipv6(packet + payload_offset, payload_len);
            break;
        default : 
            std::cout << "\033[1;31mUnknown Ethernet Type:\033[0m " << std::hex << ether_type  << "\n" << std::endl;
    }

}


/**
 * Parses the IPv4 header for src and dst IP addresses, protocol, and other relevant information.
 */
void PacketParser::parse_Ipv4(const u_char *packet, int packet_len){
    // TODO : Implement IPv4 header parsing to extract source/destination IPs, protocol, etc.
    unsigned char byte1 = packet[0];
    unsigned char version = (byte1 >> 4) && 0x0F;
    unsigned char ihl = byte1 && 0x0F;

    unsigned char byte2 = packet[1];
    unsigned char dscp = (byte2 >> 2) && 0xFF;
    unsigned char ecn = byte2 && 0x03;
    
    uint16_t total_length = ntohs(*(uint16_t *)(packet+2));
    uint16_t id = ntohs(*(uint16_t *)(packet+4));
    unsigned char flags = (packet[5] >> 5)&&0x07;
    uint16_t frameoffset = ntohs(*(uint16_t *)(packet+6)) && 0x1FFF;
    
    unsigned char ttl = packet[8];
    unsigned char protocol = packet[9];
    uint16_t checksum = ntohs(*(uint16_t *)(packet+10));

    uint32_t src_ip = ntohl(*(uint32_t *)(packet+12));
    uint32_t dst_ip = ntohl(*(uint32_t *)(packet+16));

    std::cout << "\033[1;33mIPv4 Header:\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Version :  " << std::dec << (int)version << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m IHL :  " << std::dec << (int)ihl << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m DSCP :  " << std::dec << (int)dscp << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m ECN :  " << std    ::dec << (int)ecn << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Total Length :  " << std::dec << total_length << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Identification :  " << std::dec << id << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Flags :  " << std::dec << (int)flags << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Fragment Offset :  " << std::dec << frameoffset << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m TTL :  " << std::dec << (int)ttl << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Protocol :  " << std::dec << (int)protocol << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Header Checksum :  " << std::hex << checksum << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Source IP :  " << std  ::dec << ((src_ip >> 24) & 0xFF) << "." << ((src_ip >> 16) & 0xFF) << "." << ((src_ip >> 8) & 0xFF) << "." << (src_ip & 0xFF) << "\033[0m\n" << std::endl;
    std::cout << "\033[1;31m Destination IP :  " << std  ::dec << ((dst_ip >> 24) & 0xFF) << "." << ((dst_ip >> 16) & 0xFF) << "." << ((dst_ip >> 8) & 0xFF) << "." << (dst_ip & 0xFF) << "\033[0m\n" << std::endl;
    
}


/**
 * Parses the IPv6 header for src and dst IP addresses, protocol, and other relevant information.
 */
void PacketParser::parse_Ipv6(const u_char *packet, int packet_len){
    // TODO : Implement IPv6 header parsing to extract source/destination IPs, protocol, etc.
}