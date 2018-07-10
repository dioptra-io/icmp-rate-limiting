//
// Created by System Administrator on 04/07/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_SNIFFER_T_HPP
#define ICMPRATELIMITING_RATE_LIMIT_SNIFFER_T_HPP
#include <string>
#include <tins/tins.h>

class rate_limit_sniffer_t {
public:

    explicit rate_limit_sniffer_t(const Tins::NetworkInterface & , const std::vector<Tins::IPv4Address> &);
    void set_pcap_file(const std::string &);
    void add_destination(const Tins::IPv4Address &);
    void start();
    void set_stop_sniffing(bool);
    void join();
    const std::string &get_pcap_file() const ;

private:

    bool handler(Tins::PDU& packet);

    Tins::NetworkInterface interface;
    std::vector<Tins::IPv4Address> destinations;
    std::unique_ptr<Tins::Sniffer> sniffer_ptr;
    std::thread sniffer_thread;
    std::vector <Tins::EthernetII> sniffed_packets;
    std::atomic<bool> stop_sniffing;
    std::string pcap_file;

};


#endif //ICMPRATELIMITING_RATE_LIMIT_SNIFFER_T_HPP
