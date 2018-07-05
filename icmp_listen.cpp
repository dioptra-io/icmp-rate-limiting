//
// Created by System Administrator on 28/06/2018.
//

#include <string>
#include <iostream>
#include <csignal>

#include <tins/tins.h>


using namespace Tins;

namespace{
    std::vector <EthernetII> sniffed_packets;
}

void sigint_handler(int signo){
    PacketWriter writer("resources/test.pcap", DataLinkType<EthernetII>());
    std::for_each(sniffed_packets.begin(), sniffed_packets.end(),[&writer](EthernetII pdu){
       writer.write(pdu);
    });
}

bool handler(PDU& packet) {
    // Search for it. If there is no IP PDU in the packet,
    // the loop goes on
    sniffed_packets.push_back(packet.rfind_pdu<EthernetII>());
    std::cout << sniffed_packets.size() << "\n";
    return true;
}


int main(int argc, char ** argv){

    auto destination  = std::string{argv[1]};
    auto destination_alias  = std::string{argv[2]};
    sniffed_packets.reserve(100000);
    if (signal(SIGINT, sigint_handler) == SIG_ERR) {
        fputs("An error occurred while setting a signal handler.\n", stderr);
        return EXIT_FAILURE;
    }
    if (signal(SIGTERM, sigint_handler) == SIG_ERR) {
        fputs("An error occurred while setting a signal handler.\n", stderr);
        return EXIT_FAILURE;
    }
    if (signal(SIGQUIT, sigint_handler) == SIG_ERR) {
        fputs("An error occurred while setting a signal handler.\n", stderr);
        return EXIT_FAILURE;
    }
    // Create sniffer configuration object.
    SnifferConfiguration config;
    config.set_filter("icmp or (udp and dst " + destination+") or (udp and dst " + destination_alias + ")");
    config.set_immediate_mode(true);

    // Construct a Sniffer object, using the configuration above.
    Sniffer sniffer("en7", config);
    sniffer.sniff_loop(handler);


}
