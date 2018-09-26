//
// Created by System Administrator on 04/07/2018.
//

#include <string>
#include <thread>
#include <iostream>
#include <sstream>
#include "../include/rate_limit_sniffer_t.hpp"
#include "utils/tins_utils_t.hpp"
using namespace Tins;
using namespace utils;


rate_limit_sniffer_t::rate_limit_sniffer_t(const Tins::NetworkInterface & interface):
        interface(interface)
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
    if (!destinations4.empty()){
        filter_stream << "icmp";
    } else if (!destinations6.empty()){
        filter_stream << "icmp6";
    }

    for (const auto & destination: destinations4) {
        filter_stream << " or (dst " + destination.to_string() + ")";
    }
    for (const auto & destination: destinations6) {
        filter_stream << " or (dst " + destination.to_string() + ")";
    }
    config.set_filter(filter_stream.str());
    sniffer_ptr = std::make_unique<Sniffer>(interface.name(), config);
    // Launch sniffing thread.
    sniffer_thread = std::thread{([&]() {
        sniffer_ptr->sniff_loop(utils::make_sniffer_handler(this,  &rate_limit_sniffer_t::handler));
    })};
}


bool rate_limit_sniffer_t::handler(Packet& packet) {
    // Search for it. If there is no IP PDU in the packet,
    // the loop goes on
    sniffed_packets.push_back(packet);
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
    std::unique_ptr<PDU> kill_thread_packet;
    if (!destinations4.empty()){
        kill_thread_packet = std::make_unique<IP>(IP(*destinations4.begin())/ICMP());
    }
    else if (!destinations6.empty()){
        kill_thread_packet = std::make_unique<IPv6>(IPv6(*destinations6.begin())/ICMPv6());
    }
    sender.send(*kill_thread_packet);
    sniffer_thread.join();
    // Write the results into a file.
    Tins::PacketWriter packet_writer{pcap_file, Tins::DataLinkType<Tins::EthernetII>()};
    for (auto & packet: sniffed_packets){
        packet_writer.write(packet);
    }
}

void rate_limit_sniffer_t::add_destination(const probe_infos_t & probe_infos) {
    if (probe_infos.get_family() == PDU::PDUType::IP){
        destinations4.insert(probe_infos.get_real_target4());
    } else if (probe_infos.get_family() == PDU::PDUType::IPv6){
        destinations6.insert(probe_infos.get_real_target6());
    }

}

rate_limit_sniffer_t::rate_limit_sniffer_t(const rate_limit_sniffer_t & copy_sniffer) :
        interface(copy_sniffer.interface),
        destinations4(copy_sniffer.destinations4),
        sniffer_ptr(),
        sniffer_thread(),
        sniffed_packets(),
        stop_sniffing(false),
        pcap_file(copy_sniffer.pcap_file)
{

}


