////
//// Created by System Administrator on 10/07/2018.
////
//
//#include <tins/network_interface.h>
//#include "../include/rate_limit_test_t.hpp"
//#include "utils/container_utils_t.hpp"
//
//using namespace utils;
//using namespace Tins;
//
//namespace{
//    std::unordered_map<IPv4Address, IP> probes_infos_to_tins_ip(const std::unordered_map<IPv4Address, probe_infos_t> & probes_map){
//        std::unordered_map<IPv4Address, IP> tins_ip_map;
//        std::transform(probes_map.begin(), probes_map.end(), std::inserter(tins_ip_map, tins_ip_map.end()),
//                       [](const auto & probe_infos ){
//            return std::make_pair(probe_infos.first, probe_infos.second.get_packet());
//        });
//        return tins_ip_map;
//    }
//}
//
//rate_limit_test_t::rate_limit_test_t(int nb_probes, int probing_rate, const NetworkInterface &iface,
//                                     const std::vector <probe_infos_t> & probes):
//        rate_limit_sender{nb_probes, probing_rate, iface, probes},
//        rate_limit_sniffer{iface, std::unordered_set<Tins::IPv4Address>()},
//        rate_limit_analyzer{probing_style_t::DIRECT}
//{
//    for (const auto & probe : probes ){
//        rate_limit_sniffer.add_destination(probe.get_packet4().dst_addr());
//    }
//}
//
//rate_limit_test_t::rate_limit_test_t(int nb_probes, int probing_rate, const NetworkInterface &iface,
//                                     const std::unordered_map<IPv4Address, probe_infos_t> &probes):
//    rate_limit_sender{nb_probes, probing_rate, iface, values(probes)},
//    rate_limit_sniffer{iface, std::unordered_set<Tins::IPv4Address>()},
//    rate_limit_analyzer{probing_style_t::INDIRECT, probes_infos_to_tins_ip(probes)}
//{
//    for (const auto & probe : probes ){
//        rate_limit_sniffer.add_destination(probe.second.get_packet().dst_addr());
//    }
//}
//
//
//void rate_limit_test_t::set_pcap_file(const std::string &new_pcap_file){
//    rate_limit_sniffer.set_pcap_file(new_pcap_file);
//}
//
//const std::string &rate_limit_test_t::get_pcap_file() const {
//    return rate_limit_sniffer.get_pcap_file();
//}
//
//void rate_limit_test_t::start() {
//
//    rate_limit_sniffer.set_stop_sniffing(false);
//    rate_limit_sniffer.start();
//    rate_limit_sender.start();
//    rate_limit_sniffer.set_stop_sniffing(true);
//    rate_limit_sniffer.join();
//    rate_limit_analyzer.start(get_pcap_file());
////    rate_limit_analyzer.dump_loss_rate();
////    rate_limit_analyzer.dump_time_series();
////    rate_limit_analyzer.dump_gilbert_eliot();
//
//}
//
