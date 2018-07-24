//
// Created by System Administrator on 10/07/2018.
//

#include <tins/network_interface.h>
#include "../include/rate_limit_test_t.hpp"
#include "utils/container_utils_t.hpp"

using namespace utils;

rate_limit_test_t::rate_limit_test_t(int nb_probes, int probing_rate, const Tins::NetworkInterface &iface,
                                     const std::vector <Tins::IP> &candidates,
                                     const std::vector <Tins::IP> &options_ips):
        rate_limit_sender{nb_probes, probing_rate, iface, candidates, options_ips},
        rate_limit_sniffer{iface, std::unordered_set<Tins::IPv4Address>()},
        rate_limit_analyzer{rate_limit_analyzer_t::probing_style_t::DIRECT}
{
    for (const auto & candidate : candidates ){
        rate_limit_sniffer.add_destination(candidate.dst_addr());
    }

    for (const auto & options_ip: options_ips){
        rate_limit_sniffer.add_destination(options_ip.dst_addr());
    }
}

rate_limit_test_t::rate_limit_test_t(int nb_probes, int probing_rate, const Tins::NetworkInterface &iface,
                                     const std::unordered_map<Tins::IPv4Address, Tins::IP> &candidates,
                                     const std::unordered_map<Tins::IPv4Address, Tins::IP> &options_ips):
    rate_limit_sender{nb_probes, probing_rate, iface, values(candidates), values(options_ips)},
    rate_limit_sniffer{iface, std::unordered_set<Tins::IPv4Address>()},
    rate_limit_analyzer{rate_limit_analyzer_t::probing_style_t::INDIRECT, extend(candidates, options_ips)}
{
    for (const auto & candidate : candidates ){
        rate_limit_sniffer.add_destination(candidate.second.dst_addr());
    }

    for (const auto & options_ip: options_ips){
        rate_limit_sniffer.add_destination(options_ip.second.dst_addr());
    }
}


void rate_limit_test_t::set_pcap_file(const std::string &new_pcap_file){
    rate_limit_sniffer.set_pcap_file(new_pcap_file);
}

const std::string &rate_limit_test_t::get_pcap_file() const {
    return rate_limit_sniffer.get_pcap_file();
}

rate_limit_test_t::rate_limit_test_t(const rate_limit_sender_t & sender,
                                     const rate_limit_sniffer_t & sniffer,
                                     const rate_limit_analyzer_t & analyzer):
        rate_limit_sender(sender), rate_limit_sniffer(sniffer), rate_limit_analyzer(analyzer) {

}

rate_limit_test_t rate_limit_test_t::reverse() const {
    rate_limit_sender_t reverse_sender = rate_limit_sender.reverse();
    rate_limit_sniffer_t sniffer = rate_limit_sniffer_t(rate_limit_sniffer);
    rate_limit_analyzer_t analyzer = rate_limit_analyzer_t(rate_limit_analyzer.get_probing_style());
    return rate_limit_test_t(reverse_sender, sniffer, analyzer);
}

void rate_limit_test_t::start() {

    rate_limit_sniffer.set_stop_sniffing(false);
    rate_limit_sniffer.start();
    rate_limit_sender.start();
    rate_limit_sniffer.set_stop_sniffing(true);
    rate_limit_sniffer.join();
    rate_limit_analyzer.start(get_pcap_file());
    rate_limit_analyzer.dump_loss_rate();
    rate_limit_analyzer.dump_time_series();
    rate_limit_analyzer.dump_gilbert_eliot();

}

