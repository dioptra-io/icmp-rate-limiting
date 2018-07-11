//
// Created by System Administrator on 04/07/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_TEST_T_HPP
#define ICMPRATELIMITING_RATE_LIMIT_TEST_T_HPP

#include <thread>
#include <iostream>
#include <string>
#include <tins/tins.h>
#include "rate_limit_sender_t.hpp"
#include "rate_limit_sniffer_t.hpp"
#include "rate_limit_analyzer_t.hpp"
#include "probe_t.hpp"

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
                      const std::vector<Tins::IP> & candidates,
                      const std::vector<Tins::IP> & options_ips
                      );


    /**
     * Configurable probing test (ICMP, UDP, TCP) indirect probing style
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
                      const std::unordered_map<Tins::IPv4Address, Tins::IP> & candidates,
                      const std::unordered_map<Tins::IPv4Address, Tins::IP> & options_ips
    );


    rate_limit_test_t(const rate_limit_sender_t & , const rate_limit_sniffer_t & , const rate_limit_analyzer_t &);

    rate_limit_test_t reverse() const ;
    /**
     * Starts the test
     * @param sender
     */
    void start();

    void set_pcap_file(const std::string &new_pcap_file);
    const std::string & get_pcap_file() const;


private:
    // Sender
    rate_limit_sender_t rate_limit_sender;

    // Sniffer
    rate_limit_sniffer_t rate_limit_sniffer;

    // Analyzer
    rate_limit_analyzer_t rate_limit_analyzer;



};

#endif //ICMPRATELIMITING_RATE_LIMIT_TEST_HPP
