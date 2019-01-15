//
// Created by System Administrator on 10/07/2018.
//

#include <tins/tins.h>
#include <thread>
#include <iostream>
#include <algorithm>// std::random_shuffle
#include <random>
#include <unistd.h>

#include <rate_limit_sender_t.hpp>
#include <utils/maths_utils_t.hpp>
#include <boost/concept_check.hpp>

using namespace utils;
using namespace Tins;

namespace{

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

std::vector<IP> rate_limit_sender_t::build_probing_pattern4(int nb_probes) {
    std::vector<IP> probing_pattern;
    std::default_random_engine random_engine;
    while (probing_pattern.size() < nb_probes){
        std::vector<IP> batch;
        for (const auto & candidate : candidates){
            for (int i = 0; i < candidate.get_probing_rate(); ++i){
                batch.push_back(candidate.get_packet4());
            }
        }

        std::shuffle(std::begin(batch), std::end(batch), random_engine);
        for (auto & packet : batch){
            probing_pattern.push_back(std::move(packet));
        }
    }


    uint16_t start_ip_id = 34232;

    uint16_t seq = 1;
    uint16_t ip_id = start_ip_id;
    uint16_t icmp_id = 1;
    for (int i = 0; i < probing_pattern.size(); ++i, ++seq) {
        probing_pattern[i].id(ip_id);
        // Hack for working of PlanetLab, there are restriction to packets that are emitted with same IP-ID.
        if (seq % 5 == 0) {
            ++icmp_id;
        }
        auto icmp = probing_pattern[i].find_pdu<ICMP>();
        if (icmp != nullptr){
            icmp->id(icmp_id);
            icmp->sequence(seq);
        } else {
            probing_pattern[i].id(seq);
        }
    }
    return probing_pattern;
}

std::vector<IPv6> rate_limit_sender_t::build_probing_pattern6(int nb_probes) {
    std::vector<IPv6> probing_pattern;
    std::default_random_engine random_engine;
    while (probing_pattern.size() < nb_probes){
        std::vector<IPv6> batch;
        for (const auto & candidate : candidates){
            for (int i = 0; i < candidate.get_probing_rate(); ++i){
                batch.push_back(candidate.get_packet6());
            }
        }

        std::shuffle(std::begin(batch), std::end(batch), random_engine);
        for (auto & packet : batch){
            probing_pattern.push_back(std::move(packet));
        }
    }

    uint16_t start_ip_id = 34232;

    uint16_t seq = 1;
    uint16_t ip_id = start_ip_id;
    uint16_t icmp_id = 1;

    for (int i = 0; i < probing_pattern.size(); ++i, ++seq) {
        if (seq % 5 == 0) {
            ++icmp_id;
        }
        auto icmp = probing_pattern[i].find_pdu<ICMPv6>();
        if (icmp != nullptr){
            icmp->identifier(icmp_id);
            icmp->sequence(seq);
        } else {

        }
    }



    return probing_pattern;
}

void rate_limit_sender_t::start() {

        // 1 packet / interval
    auto interval = 1000000/probing_rate;

    int probe_sent = 0;

    std::vector<double> loop_overheads;

    IP warmup_probe {NetworkInterface::default_interface().ipv4_address(), NetworkInterface::default_interface().ipv4_address()};
    IPv6 warmup_probe6 {NetworkInterface::default_interface().ipv6_addresses()[0].address,
                        NetworkInterface::default_interface().ipv6_addresses()[0].address};

    uint16_t start_ip_id = 34232;
    // Warm up to compute the loop overhead of sending a packet
    for (int i = 0; i < 2000; ++i) {

        auto start_send_packet = std::chrono::high_resolution_clock::now();

        if (candidates[0].get_family() == PDU::PDUType::IP){
            auto probe_to_send = warmup_probe;
//            auto icmp = probe_to_send.find_pdu<ICMP>();
//            if (icmp != nullptr) {
//                icmp->id(1);
//                icmp->sequence(i);
//            } else {
//                probe_to_send.id(i);
//            }

            sender.send(probe_to_send);
        } else if (candidates[0].get_family() == PDU::PDUType::IPv6){
            auto probe_to_send = warmup_probe6;
//            auto icmp = probe_to_send.find_pdu<ICMPv6>();
//            if (icmp != nullptr){
//                icmp->identifier(1);
//                icmp->sequence(i);
//            }
            sender.send(probe_to_send);
        }


        auto end_send_packet = std::chrono::high_resolution_clock::now();
        loop_overheads.push_back(std::chrono::duration<double, std::micro> (end_send_packet-start_send_packet).count());
    }

    // Adjust the sleep time according to the loop overhead
    double loop_overhead = mean_stddev(loop_overheads.begin(), loop_overheads.end()).first;
    if (loop_overhead < interval){
        interval -= loop_overhead;
    } else{
        interval = 1;
    }


    std::cout << "Loop overhead is: " << loop_overhead <<" us\n";


    // v4
    if (candidates[0].get_family() == PDU::PDUType::IP){
        // Initialization of the pattern that will be sent.
        auto probing_pattern = build_probing_pattern4(nb_probes);

        auto start = std::chrono::high_resolution_clock::now();


        for (int i = 0; i < probing_pattern.size(); ++i){
//            std::cout << static_cast<ICMP*>(probing_pattern[i].inner_pdu())->id() << "\n";
//            std::cout << static_cast<ICMP*>(probing_pattern[i].inner_pdu())->sequence() << "\n";
            try{
                sender.send(probing_pattern[i]);
            } catch (const socket_write_error & e){
                std::cout << e.what() << "\n";
            }


            wait_loop(interval);
            if (i == nb_probes - 1){
                auto end = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double, std::milli> elapsed = end-start;
                std::cout << "Sending took " << elapsed.count() << " ms\n";
            }

        }
        // v6
    }  else if (candidates[0].get_family() == PDU::PDUType::IPv6){

        // Initialization of the pattern that will be sent.
        auto probing_pattern = build_probing_pattern6(nb_probes);
        auto start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < probing_pattern.size(); ++i){

            sender.send(probing_pattern[i]);

            wait_loop(interval);
            if (i == nb_probes - 1){
                auto end = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double, std::milli> elapsed = end-start;
                std::cout << "Sending took " << elapsed.count() << " ms\n";
            }

        }
    }

}








