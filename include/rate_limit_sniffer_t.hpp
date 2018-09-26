//
// Created by System Administrator on 04/07/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_SNIFFER_T_HPP
#define ICMPRATELIMITING_RATE_LIMIT_SNIFFER_T_HPP
#include <string>
#include <unordered_set>
#include <thread>
#include <sstream>
#include <atomic>


#include <tins/tins.h>

#include <utils/tins_utils_t.hpp>


class rate_limit_sniffer_t {

public:

    explicit rate_limit_sniffer_t(const Tins::NetworkInterface & interface);

    rate_limit_sniffer_t(const rate_limit_sniffer_t & copy_sniffer);
    void set_pcap_file(const std::string &new_output_file);
    void set_stop_sniffing(bool new_stop_sniffing);

    void start();

    const std::string &get_pcap_file() const;

    void join();

    void add_destination(const probe_infos_t & destination);



private:

    bool handler(Tins::Packet& packet);

    Tins::NetworkInterface interface;
    std::unordered_set<Tins::IPv4Address> destinations4;
    std::unordered_set<Tins::IPv6Address> destinations6;
    std::unique_ptr<Tins::Sniffer> sniffer_ptr;
    std::thread sniffer_thread;
    std::vector <Tins::Packet> sniffed_packets;
    std::atomic<bool> stop_sniffing;
    std::string pcap_file;

};
#endif //ICMPRATELIMITING_RATE_LIMIT_SNIFFER_T_HPP
