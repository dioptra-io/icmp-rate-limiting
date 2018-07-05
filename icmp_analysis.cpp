//
// Created by System Administrator on 28/06/2018.
//

#include <tins/tins.h>
#include <unordered_map>
#include <iostream>
#include <algorithm>

using namespace Tins;

namespace{
    std::vector<Packet> outgoing_packets;
    std::vector<Packet> icmp_replies;
}

bool build_series(Packet & packet){
    auto pdu = packet.pdu();
    auto icmp = pdu->find_pdu<ICMP>();
    if (icmp == NULL or icmp->type() == ICMP::Flags::ECHO_REQUEST){
        outgoing_packets.push_back(packet);
    } else {
        icmp_replies.push_back(packet);
    }
    return true;
}

void sort_by_timestamp(std::vector<Timestamp> & timestamps){
    std::sort(timestamps.begin(), timestamps.end(), [](const Timestamp & timestamp1, const Timestamp & timestamp2){
        return std::chrono::microseconds(timestamp1).count() < std::chrono::microseconds(timestamp2).count();
    });
}

void sort_by_timestamp(std::vector<Packet> & packets){
    std::sort(packets.begin(), packets.end(), [](const Packet & packet1, const Packet & packet2){
        return std::chrono::microseconds(packet1.timestamp()).count() < std::chrono::microseconds(packet2.timestamp()).count();
    });
}

int main(int argc, char ** argv){

    auto pcap_file = std::string{argv[1]};
    // This one corresponds to the first flow (24000)
    auto ip1 = IPv4Address{argv[2]};
    // This one corresponds to the first flow (24001)
    auto ip2 = IPv4Address{argv[3]};
    // Read the pcap file and reconstruct a serie
    FileSniffer sniffer(pcap_file);
    sniffer.sniff_loop(build_series);

    // Find the responding windows for the 2 interfaces.
    using responsiveness = std::vector<Timestamp>;
    std::unordered_map<IPv4Address, responsiveness> responsiveness_by_ip;
    std::unordered_map<IPv4Address, responsiveness> unresponsiveness_by_ip;
    // Matches probe with replies and extract responsiveness
    sort_by_timestamp(outgoing_packets);
    for(const auto & packet : outgoing_packets){
        auto outgoing_pdu = packet.pdu();
        auto ip = outgoing_pdu->rfind_pdu<IP>();
//        auto udp = ip.rfind_pdu<UDP>();
        auto icmp_echo = ip.rfind_pdu<ICMP>();
        auto it = std::find_if(icmp_replies.begin(), icmp_replies.end(), [&ip, &icmp_echo](const Packet & matching_packet){
            auto pdu = matching_packet.pdu();
            auto icmp = pdu->find_pdu<ICMP>();
            auto inner_raw = pdu->find_pdu<RawPDU>();

            try{
                if (icmp->id() == icmp_echo.id()){
                    return true;
                }
//                auto inner_ip = inner_raw->to<IP>();
//                //auto inner_udp = inner_ip.rfind_pdu<UDP>();
//                if (inner_ip.id() == ip.id()){
//                    return true;
//                }
            } catch (const malformed_packet & e){
                std::cerr << e.what() << "\n";
            }
            return false;
        });
        if (it != icmp_replies.end()){
            auto ip_reply = it->pdu()->rfind_pdu<IP>().src_addr();
//            if (responsiveness_by_ip.find(ip_reply) == responsiveness_by_ip.end()){
//                std::vector<Timestamp> timestamps{packet.timestamp()};
//                responsiveness_by_ip.emplace(std::make_pair(ip_reply, timestamps));
//            } else {
//                responsiveness_by_ip[ip_reply].push_back(packet.timestamp());
//            }
            // Erase this response.
            icmp_replies.erase(it);
            std::cout << "Responsive " << ip_reply << " " <<  std::chrono::microseconds(packet.timestamp()).count() << "\n";
        } else {
            // Match the ip reply by the flow identifier
//            auto sport = udp.sport();
//            IPv4Address indirect_ip;
//            if (sport == 24000){
//                indirect_ip = ip1;
//            } else if (sport == 24001){
//                indirect_ip = ip2;
//            }

            //Match the ip reply with the destination
            auto dst_ip = ip.dst_addr();

//            if (unresponsiveness_by_ip.find(indirect_ip) == unresponsiveness_by_ip.end()){
//                std::vector<Timestamp> timestamps{packet.timestamp()};
//                unresponsiveness_by_ip.emplace(std::make_pair(indirect_ip, timestamps));
//            } else {
//                unresponsiveness_by_ip[indirect_ip].push_back(packet.timestamp());
//            }
            std::cout << "Unresponsive " << dst_ip << " " <<  std::chrono::microseconds(packet.timestamp()).count() << "\n";

        }
    }
    // Extract the periods when ip1 is not responsive
//    std::for_each(responsiveness_by_ip.begin(), responsiveness_by_ip.end(), [](auto & responsiveness){
//
//        sort_by_timestamp(responsiveness.second);
//
////       for(const auto & timestamp : responsiveness.second){
////           std::cout << std::chrono::microseconds(timestamp).count() << "\n";
////       }
//    });
//
//    std::for_each(unresponsiveness_by_ip.begin(), unresponsiveness_by_ip.end(), [](auto & responsiveness){
//
//        sort_by_timestamp(responsiveness.second);
//        std::cout << responsiveness.first << "\n\n\n";
//       for(const auto & timestamp : responsiveness.second){
//           std::cout << std::chrono::microseconds(timestamp).count() << "\n";
//       }
//    });





}