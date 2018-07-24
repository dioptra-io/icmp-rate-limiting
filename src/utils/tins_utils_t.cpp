//
// Created by System Administrator on 24/07/2018.
//

#include <iostream>
#include "../../include/utils/tins_utils_t.hpp"

using namespace Tins;
namespace utils{
    std::unordered_map<Tins::IPv4Address, Tins::IP> retrieve_matchers(const IPv4Address & test_ip, const std::string & absolute_path){
        std::unordered_map<IPv4Address, IP> matchers;
        try{
            FileSniffer sniffer(absolute_path);
            Packet first_packet {sniffer.next_packet()};
            // The first packet is supposed to be a probe packet.
            if (first_packet.pdu() != nullptr){
                // Extract the protocol and type infos.
                auto first_pdu = first_packet.pdu();
                auto ip = first_pdu->find_pdu<IP>();
                auto udp = ip->find_pdu<UDP>();
                if (udp != nullptr){
                    // This is udp, figure out if this was direct or indirect by looking at the destination
                    IP probe = IP(ip->dst_addr(), ip->src_addr()) /UDP(udp->dport(), udp->dport());
                    probe.ttl(ip->ttl());
                    if (ip->dst_addr() == IPv4Address(test_ip)){
                        // We are in a direct test.
                        matchers.insert(std::make_pair(ip->dst_addr(), probe));
                    } else{
                        matchers.insert(std::make_pair(test_ip, probe));
                    }

                } else {
                    auto icmp = ip->find_pdu<ICMP>();
                    if (icmp != nullptr){
                        IP probe = IP(ip->dst_addr(), ip->src_addr())/ ICMP();
                        probe.ttl(ip->ttl());
                        matchers.insert(std::make_pair(ip->dst_addr(), probe));
                    } else {
                        std::cerr << "Can not recognize the type of probing.\n";
                    }
                }
            }


        } catch (const pcap_error & e) {
            std::cerr << e.what() << "\n";
        }
        return matchers;
    }
}

