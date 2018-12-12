//
// Created by System Administrator on 04/07/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_TEST_T_HPP
#define ICMPRATELIMITING_RATE_LIMIT_TEST_T_HPP

#include <thread>
#include <iostream>
#include <string>
#include <tins/tins.h>
#include <rate_limit_sender_t.hpp>
#include <rate_limit_sniffer_t.hpp>
#include <rate_limit_analyzer_t.hpp>
#include <probe_infos_t.hpp>
#include <utils/container_utils_t.hpp>

class rate_limit_test_t{
public:

    /**
     * Configurable probing test (ICMP, UDP, TCP) direct probing style
     *
     * @param nb_probes
     * @param probing_rate
     * @param iface
     * @param candidates
     * @param options_ips
     */

    rate_limit_test_t(int nb_probes,
                      int probing_rate,
                      const Tins::NetworkInterface & iface,
                      const std::vector<probe_infos_t> & probes):
            rate_limit_sender{nb_probes, probing_rate, iface, probes},
            rate_limit_sniffer{iface}
    {
        for (const auto & probe : probes ){
            rate_limit_sniffer.add_destination(probe);
        }
    }



    /**
     * Configurable probing test (ICMP, UDP, TCP) indirect probing style
     *
     * @param nb_probes
     * @param probing_rate
     * @param iface
     * @param candidates
     * @param options_ips
     */

//    rate_limit_test_t(int nb_probes, int probing_rate, const Tins::NetworkInterface &iface,
//                                         const std::unordered_map<IPvAddress, probe_infos_t> &probes):
//            rate_limit_sender{nb_probes, probing_rate, iface, utils::values(probes)},
//            rate_limit_sniffer{iface}
//    {
//        for (const auto & probe : probes ){
//            rate_limit_sniffer.add_destination(probe.second.get_packet().dst_addr());
//        }
//    }


    void set_pcap_file(const std::string &new_pcap_file){
        rate_limit_sniffer.set_pcap_file(new_pcap_file);
    }

    const std::string &get_pcap_file() const {
        return rate_limit_sniffer.get_pcap_file();
    }

    /**
     * Starts the test
     * @param sender
     */
    void start() {

        rate_limit_sniffer.set_stop_sniffing(false);
        rate_limit_sniffer.start();
        rate_limit_sender.start();

        // Wait for the last packet to get a possible answer
        std::this_thread::sleep_for(std::chrono::seconds(1));

        rate_limit_sniffer.set_stop_sniffing(true);
        rate_limit_sniffer.join();
        //rate_limit_analyzer.start(get_pcap_file());
//    rate_limit_analyzer.dump_loss_rate();
//    rate_limit_analyzer.dump_time_series();
//    rate_limit_analyzer.dump_gilbert_eliot();

    }


    // Indirect only available in v4
    std::unordered_map<Tins::IPv4Address, Tins::IP> probes_infos_to_tins_ip(const std::unordered_map<Tins::IPv4Address, probe_infos_t> & probes_map){
        std::unordered_map<Tins::IPv4Address, Tins::IP> tins_ip_map;
        std::transform(probes_map.begin(), probes_map.end(), std::inserter(tins_ip_map, tins_ip_map.end()),
                       [](const auto & probe_infos ){
                           return std::make_pair(probe_infos.first, probe_infos.second.get_packet4());
                       });
        return tins_ip_map;
    }


private:
    // Sender
    rate_limit_sender_t rate_limit_sender;

    // Sniffer
    rate_limit_sniffer_t rate_limit_sniffer;

};

#endif //ICMPRATELIMITING_RATE_LIMIT_TEST_HPP
