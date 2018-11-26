//
// Created by System Administrator on 10/07/2018.
//

#include <tins/tins.h>
#include <thread>
#include <iostream>
#include <algorithm>// std::random_shuffle
#include <random>
#include <rate_limit_sender_t.hpp>

using namespace Tins;

namespace{
    int potential_alias_packets = 50;

    void wait_loop(int interval){
        bool sleep = true;
        auto start_loop = std::chrono::system_clock::now();

        // This is an active waiting but more precise than sleep().
        while(sleep)
        {
            auto now = std::chrono::system_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - start_loop);
            if ( elapsed.count() > interval ){
                sleep = false;
            }

        }
    }

}

rate_limit_sender_t::rate_limit_sender_t(int nb_probes, int probing_rate, const Tins::NetworkInterface &iface,
                                         const std::vector<probe_infos_t> &candidates):
        nb_probes{nb_probes},
        probing_rate{probing_rate},
        sending_iface{iface},
        candidates{candidates},
        sender(iface)
//        sender(AF_INET, SOCK_RAW, candidates[0].get_packet4().protocol())
{
//    sender.set_buffer_size(sender.get_buffer_size(SO_SNDBUF) * 256);
}

rate_limit_sender_t::rate_limit_sender_t(const rate_limit_sender_t &copy_rate_limit_sender):
        nb_probes{copy_rate_limit_sender.nb_probes},
        probing_rate{copy_rate_limit_sender.probing_rate},
        sending_iface{copy_rate_limit_sender.sending_iface},
        candidates{copy_rate_limit_sender.candidates},
        sender(copy_rate_limit_sender.sending_iface)
//        sender{AF_INET, SOCK_RAW, candidates[0].get_packet().protocol()}
{
//    sender.set_buffer_size(sender.get_buffer_size(SO_SNDBUF) * 256);
}

std::vector<IP> rate_limit_sender_t::build_probing_pattern4() {
    std::vector<IP> probing_pattern;
    for (const auto & candidate : candidates){
        for (int i = 0; i < candidate.get_probing_rate(); ++i){
            probing_pattern.push_back(candidate.get_packet4());
        }
    }

    std::default_random_engine random_engine;
    std::shuffle(std::begin(probing_pattern), std::end(probing_pattern), random_engine);
    return probing_pattern;
}

std::vector<IPv6> rate_limit_sender_t::build_probing_pattern6() {
    std::vector<IPv6> probing_pattern;
    for (const auto & candidate : candidates){
        for (int i = 0; i < candidate.get_probing_rate(); ++i){
            probing_pattern.push_back(candidate.get_packet6());
        }
    }

    std::default_random_engine random_engine;
    std::shuffle(std::begin(probing_pattern), std::end(probing_pattern), random_engine);
    return probing_pattern;
}

void rate_limit_sender_t::start() {
    // 1 packet / interval
    auto interval = 1000000/probing_rate;
    int probe_sent = 0;

    auto start = std::chrono::high_resolution_clock::now();


    // v4
    if (candidates[0].get_family() == PDU::PDUType::IP){
        // Initialization of the pattern that will be sent.
        auto probing_pattern = build_probing_pattern4();

        uint16_t ip_id = 1;

        for (int i = 0; probe_sent < nb_probes; ++i, ++probe_sent, ++ip_id){

            auto probe_to_send = probing_pattern[i%probing_pattern.size()];
            auto icmp = probe_to_send.find_pdu<ICMP>();
            if (icmp != nullptr){
                icmp->id(1);
                icmp->sequence(ip_id);
            } else {
                probe_to_send.id(ip_id);
            }

            sender.send(probe_to_send);
            wait_loop(interval);
            if (probe_sent == nb_probes - 1){
                auto end = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double, std::milli> elapsed = end-start;
                std::cout << "Sending took " << elapsed.count() << " ms\n";
            }

        }
        // v6
    }  else if (candidates[0].get_family() == PDU::PDUType::IPv6){
        auto probing_pattern = build_probing_pattern6();
        uint16_t ip_id = 1;

        for (int i = 0; probe_sent < nb_probes; ++i, ++probe_sent, ++ip_id){

            auto probe_to_send = probing_pattern[i%probing_pattern.size()];
            //TODO Only ICMPv6 is supported
            auto icmp = probe_to_send.find_pdu<ICMPv6>();
            if (icmp != nullptr){
                icmp->identifier(1);
                icmp->sequence(ip_id);
            }
            sender.send(probe_to_send);
            wait_loop(interval);
            if (probe_sent == nb_probes - 1){
                auto end = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double, std::milli> elapsed = end-start;
                std::cout << "Sending took " << elapsed.count() << " ms\n";
            }

        }

    }

}








