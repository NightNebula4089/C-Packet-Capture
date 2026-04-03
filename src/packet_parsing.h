#ifndef PACKET_PARSING_H
#define PACKET_PARSING_H

#include <string>
#include <pcap.h>

class PacketParser{
    public : 
        PacketParser(std::string device);
        void packet_parser( const struct pcap_pkthdr *header,const u_char *packet);
    
    private :
        std::string device;
};

#endif 