#ifndef PACKET_PARSING_H
#define PACKET_PARSING_H

#include <string>
#include <pcap.h>

class PacketParser{
    public : 
        PacketParser(std::string device);
        void packet_parser( const struct pcap_pkthdr *header,const u_char *packet);
        void parse_Ethernetframe(const u_char *packet, int packet_len);
    
    private :
        std::string device;
};

#endif 