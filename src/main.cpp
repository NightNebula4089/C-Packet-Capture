#include <iostream>
#include <pcap/pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "packet_parsing.h"

using namespace std;


void packet_callback(u_char *userinput, const struct pcap_pkthdr *header,const u_char *packet){
    PacketParser *parser = (PacketParser *)userinput;
    parser->packet_parser(header, packet);
}


int main(int argc, char* argv[]){

    // TODO :  Command line argument parsing 

    string device;
    int count = -1;
    int opt;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    while((opt = getopt(argc,argv,"hi:c::")) != -1){
        switch(opt) {
            case 'i' :
                device = optarg;
                break;
            case 'c' :
                count = atoi(optarg);
                break;
            case 'h':
                cout << "Usage" << argv[0] << " i [interface] c [count]" << endl;
                return 0;
            default : 
                cout << "Usage" << argv[0] << " i [interface] c [count]" << endl;
                exit(EXIT_FAILURE);
        }
    }

    // TODO : Start a live Packet Capture session on the device and capture count packets.
    pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);

    if(device.empty()){
        cout << "No device specified, choosing default device" <<endl;
        pcap_if_t *alldevs = nullptr;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            cerr << "Error finding devices: " << errbuf << endl;
            exit(EXIT_FAILURE);
        }

        if (alldevs == nullptr || alldevs->name == nullptr) {
            cerr << "No capture device available" << endl;
            if (alldevs != nullptr) {
                pcap_freealldevs(alldevs);
            }
            exit(EXIT_FAILURE);
        }

        device = alldevs->name;
        pcap_freealldevs(alldevs);

        if(device.empty()){
            cerr << "Error finding default device: " << errbuf << endl;
            exit(EXIT_FAILURE);
        }
    }

    pcap_t *handle = pcap_create(device.c_str(),errbuf);
    if((handle) == nullptr){
        cerr << "Error creating pcap handle: " << errbuf << endl;
        exit(EXIT_FAILURE);
    };
    pcap_set_promisc(handle,1);
    pcap_set_timeout(handle,1000);
    pcap_set_snaplen(handle,65535);

    if(pcap_activate(handle)!= 0){
        cout << "Error activating pcap handle:" << pcap_geterr(handle) << endl;
        pcap_close(handle);
        return 1;
    }

    PacketParser parser(device);

    if (count <= 0) count = -1;  // -1 = infinite

    cout << "Capturing packets on " << device << " (count=" << count << ")..." << endl;
    cout << "Press Ctrl+C to stop" << endl;

    pcap_loop(handle, count, packet_callback, (u_char*)&parser);

    cout << "Capture finished" << endl;
    pcap_close(handle);


    return 0;

}