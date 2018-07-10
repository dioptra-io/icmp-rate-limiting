//
// Created by System Administrator on 04/07/2018.
//

#include <string>
#include <thread>
#include <iostream>
#include <sstream>
#include "../include/rate_limit_sniffer_t.hpp"

using namespace Tins;

rate_limit_sniffer_t::rate_limit_sniffer_t(const Tins::NetworkInterface & interface, const std::vector<IPv4Address> & destinations):
        interface(interface),
        destinations(destinations)
{

}

void rate_limit_sniffer_t::set_pcap_file(const std::string &new_output_file) {
    pcap_file = new_output_file;
}

void rate_limit_sniffer_t::set_stop_sniffing(bool new_stop_sniffing) {
    stop_sniffing = new_stop_sniffing;
}

void rate_limit_sniffer_t::start() {
    Tins::SnifferConfiguration config;
    config.set_immediate_mode(true);
    std::stringstream filter_stream;
    filter_stream << "icmp";
    for (const auto & destination: destinations) {
        filter_stream << " or (dst " + destination.to_string() + ")";
    }
    config.set_filter(filter_stream.str());
    sniffer_ptr = std::make_unique<Sniffer>(interface.name(), config);
    // Launch sniffing thread.
    sniffer_thread = std::thread{([&]() {
        sniffer_ptr->sniff_loop(Tins::make_sniffer_handler(this, &rate_limit_sniffer_t::handler));
    })};
}


bool rate_limit_sniffer_t::handler(Tins::PDU& packet) {
    // Search for it. If there is no IP PDU in the packet,
    // the loop goes on
    sniffed_packets.push_back(packet.rfind_pdu<Tins::EthernetII>());
//    std::cout << sniffed_packets.size() << "\n";
    if (stop_sniffing){
        return false;
    }
    return true;
}

const std::string &rate_limit_sniffer_t::get_pcap_file() const  {
    return pcap_file;
}

void rate_limit_sniffer_t::join() {
    // Send a last ping packet here to receive a packet and stop the thread
    PacketSender sender;
    auto kill_thread_pkt = IP(destinations[0])/ICMP();
    sender.send(kill_thread_pkt);
    sniffer_thread.join();
    // Write the results into a file.
    Tins::PacketWriter packet_writer{pcap_file, Tins::DataLinkType<Tins::EthernetII>()};
    packet_writer.write(sniffed_packets.begin(), sniffed_packets.end());
}

void rate_limit_sniffer_t::add_destination(const Tins::IPv4Address & destination) {
    destinations.push_back(destination);
}


