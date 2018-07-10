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

template <typename Protocol>
class rate_limit_test_t{
public:
    /**
     * Direct probing with UDP/TCP.
     * @param nb_probes
     * @param probing_rate
     * @param dst1
     * @param dst2
     * @param sport
     * @param dport
     */
    rate_limit_test_t(int nb_probes,
                      int probing_rate,
                      const Tins::NetworkInterface & sniff_interface,
                      const Tins::IPv4Address & dst1,
                      const Tins::IPv4Address & dst2,
                      uint16_t sport, uint16_t dport):
            rate_limit_sender{nb_probes, probing_rate, dst1, dst2, sport, dport},
            rate_limit_sniffer(sniff_interface, std::vector<Tins::IPv4Address>()),
            rate_limit_analyzer()
    {
        rate_limit_sniffer.add_destination(dst1);
        rate_limit_sniffer.add_destination(dst2);
    }

    /**
     * Indirect probing with TCP/UDP.
     * @param nb_probes
     * @param probing_rate
     * @param dst1
     * @param sport1
     * @param sport2
     * @param dport
     */
    rate_limit_test_t(int nb_probes,
                      int probing_rate,
                      const Tins::NetworkInterface & sniff_interface,
                      const Tins::IPv4Address & dst,
                      const Tins::IPv4Address & indirect_dst1,
                      const Tins::IPv4Address & indirect_dst2,
                      uint8_t ttl,
                      uint16_t sport1, uint16_t sport2, uint16_t dport):
            rate_limit_sender{nb_probes, probing_rate, dst, ttl, sport1, sport2, dport},
            rate_limit_sniffer(sniff_interface, std::vector<Tins::IPv4Address>()),
            rate_limit_analyzer(std::make_tuple(sport1, ttl, indirect_dst1), std::make_tuple(sport2, ttl, indirect_dst2))
    {
        rate_limit_sniffer.add_destination(dst);
    }

    /**
     * Direct Probing with ICMP.
     * @param nb_probes
     * @param probing_rate
     * @param dst
     * @param ttl
     */
    rate_limit_test_t(int nb_probes,
                      int probing_rate,
                      const Tins::NetworkInterface & sniff_interface,
                      const Tins::IPv4Address & dst1,
                      const Tins::IPv4Address & dst2

    ):
            rate_limit_sender{nb_probes, probing_rate, dst1, dst2},
            rate_limit_sniffer(sniff_interface, std::vector<Tins::IPv4Address>()),
            rate_limit_analyzer()
    {
        rate_limit_sniffer.add_destination(dst1);
        rate_limit_sniffer.add_destination(dst2);
    }

    void start(Tins::PacketSender & sender){
        rate_limit_sniffer.set_stop_sniffing(false);
        rate_limit_sniffer.start();
        rate_limit_sender.start(sender);
        rate_limit_sniffer.set_stop_sniffing(true);
        rate_limit_sniffer.join();
        rate_limit_analyzer.start<Protocol>(get_pcap_file());
        rate_limit_analyzer.dump_loss_rate();
        rate_limit_analyzer.dump_time_series();
    }

    void set_pcap_file(const std::string &new_pcap_file){
        rate_limit_sniffer.set_pcap_file(new_pcap_file);
    }

    const std::string & get_pcap_file() const {
        return rate_limit_sniffer.get_pcap_file();
    }


    /**
     * Indirect TCP/UDP before_address
     * @param sport
     * @param dport
     * @param ttl
     * @param dst_ip
     * @param indirect_dst
     */
    void set_before_address(uint16_t sport, uint16_t dport,
                            uint8_t ttl,
                            const Tins::IPv4Address & dst_ip,
                            const Tins::IPv4Address & indirect_dst) {
        
        rate_limit_sender.set_before_hop_probe(dst_ip, ttl, sport, dport);
        rate_limit_analyzer.set_port_ttl_ip_before(std::make_tuple(sport, ttl, indirect_dst));
        
    }


    /**
     * Direct TCP/UDP before_address
     * @param sport
     * @param dport
     * @param dst_ip
     */
    void set_before_address(uint16_t sport, uint16_t dport, const Tins::IPv4Address & dst_ip) {
        rate_limit_sender.set_before_hop_probe(dst_ip, sport, dport);
        rate_limit_sniffer.add_destination(dst_ip);
    }

    /**
     * Direct ICMP before_address
     * @param dst_ip
     */
    void set_before_address(const Tins::IPv4Address & dst_ip) {
        rate_limit_sender.set_before_hop_probe(dst_ip);
    }


    /**
     * Indirect TCP/UDP after_address
     * @param sport
     * @param dport
     * @param ttl
     * @param dst_ip
     * @param indirect_dst
     */
    void set_after_address(uint16_t sport, uint16_t dport,
                            uint8_t ttl,
                            const Tins::IPv4Address & dst_ip,
                            const Tins::IPv4Address & indirect_dst) {

        rate_limit_sender.set_after_hop_probe(dst_ip, ttl, sport, dport);
        rate_limit_analyzer.set_port_ttl_ip_after(std::make_tuple(sport, ttl, indirect_dst));

    }


    /**
     * Direct TCP/UDP after_address
     * @param sport
     * @param dport
     * @param dst_ip
     */
    void set_after_address(uint16_t sport, uint16_t dport, const Tins::IPv4Address & dst_ip) {
        rate_limit_sender.set_after_hop_probe(dst_ip, sport, dport);
    }

    /**
     * Direct ICMP after_address
     * @param dst_ip
     */
    void set_after_address(const Tins::IPv4Address & dst_ip) {
        rate_limit_sender.set_after_hop_probe(dst_ip);
    }
private:
    // Sender
    rate_limit_sender_t<Protocol> rate_limit_sender;

    // Sniffer
    rate_limit_sniffer_t rate_limit_sniffer;

    // Analyzer
    rate_limit_analyzer_t rate_limit_analyzer;



};

#endif //ICMPRATELIMITING_RATE_LIMIT_TEST_HPP
