//
// Created by System Administrator on 10/07/2018.
//

#include <tins/tins.h>
#include <thread>
#include <iostream>
#include "../include/rate_limit_sender_t.hpp"

using namespace Tins;

namespace{
    int potential_alias_packets = 50;

}

rate_limit_sender_t::rate_limit_sender_t(int nb_probes, int probing_rate, const Tins::NetworkInterface &iface,
                                         const std::vector<Tins::IP> &candidates,
                                         const std::vector<Tins::IP> &options_ip):
        nb_probes{nb_probes},
        probing_rate{probing_rate},
        sending_iface{iface},
        candidates{candidates},
        options_ip{options_ip},
        sender(AF_INET, SOCK_RAW, candidates[0].protocol())
{
    sender.set_buffer_size(sender.get_buffer_size(SO_SNDBUF) * 64);
}

rate_limit_sender_t::rate_limit_sender_t(const rate_limit_sender_t &copy_rate_limit_sender):
        nb_probes{copy_rate_limit_sender.nb_probes},
        probing_rate{copy_rate_limit_sender.probing_rate},
        sending_iface{copy_rate_limit_sender.sending_iface},
        candidates{copy_rate_limit_sender.candidates},
        options_ip{copy_rate_limit_sender.options_ip},
        sender{AF_INET, SOCK_RAW, candidates[0].protocol()}
{
    sender.set_buffer_size(sender.get_buffer_size(SO_SNDBUF) * 64);
}

std::vector<Tins::IP> rate_limit_sender_t::build_probing_pattern(int N) {
    std::vector<IP> probing_pattern;
    if (N == 0){
        probing_pattern.push_back(candidates[0]);
    }

    for (int i = 0; i < N/2; ++i){
        probing_pattern.push_back(candidates[0]);
    }

    for (int i = 1; i < candidates.size(); ++i){
        probing_pattern.push_back(candidates[i]);
    }

    for (int i = 0; i < options_ip.size(); ++i){
        probing_pattern.push_back(options_ip[i]);
    }

    for(int i = N/2; i < N; ++i){
        probing_pattern.push_back(candidates[0]);
    }

    return probing_pattern;
}

void rate_limit_sender_t::start() {
    auto interval = 1000000/probing_rate;
    if(interval < 1000){
        interval = -1;
    }
    int probe_sent = 0;

    // Every N packets, we send a pair-packet.
    int N = nb_probes / potential_alias_packets;


    // Initialization of the pattern that will be sent.
    auto probing_pattern = build_probing_pattern(N);

    uint16_t ip_id = 1;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; probe_sent < nb_probes; ++i, ++probe_sent, ++ip_id){

        auto probe_to_send = probing_pattern[i%probing_pattern.size()];
        probe_to_send.id(ip_id);
        auto icmp = probe_to_send.find_pdu<ICMP>();
        if (icmp != nullptr){
            icmp->id(ip_id);
        }
        sender.send(probe_to_send);
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
        if (probe_sent == nb_probes - 1){
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::milli> elapsed = end-start;
            std::cout << "Sending took " << elapsed.count() << " ms\n";
        }

    }

}

rate_limit_sender_t rate_limit_sender_t::reverse() const  {
    std::vector<IP> reverse_candidates;
    std::reverse_copy(candidates.begin(), candidates.end(), std::back_inserter(reverse_candidates));
    return rate_limit_sender_t(nb_probes, probing_rate, sending_iface, reverse_candidates, options_ip);
}








