//
// Created by System Administrator on 04/07/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_SENDER_T_HPP
#define ICMPRATELIMITING_RATE_LIMIT_SENDER_T_HPP

#include <tins/tins.h>
#include "probe_t.hpp"

template<typename Protocol>
class rate_limit_sender_t{
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
    rate_limit_sender_t(int nb_probes,
                      int probing_rate,
                      const Tins::IPv4Address & dst1,
                      const Tins::IPv4Address & dst2,
                      uint16_t sport, uint16_t dport):
            nb_probes{nb_probes},
            probing_rate{probing_rate},
            type1_probe{dst1, 64, sport, dport},
            type2_probe{dst2, 64, sport, dport}
    {

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
    rate_limit_sender_t(int nb_probes,
                      int probing_rate,
                      const Tins::IPv4Address & dst,
                      uint8_t ttl,
                      uint16_t sport1, uint16_t sport2, uint16_t dport):
            nb_probes{nb_probes},
            probing_rate{probing_rate},
            type1_probe{dst, ttl, sport1, dport},
            type2_probe{dst, ttl, sport2, dport}
    {

    }

    /**
     * Direct Probing with ICMP.
     * @param nb_probes
     * @param probing_rate
     * @param dst
     * @param ttl
     */
    rate_limit_sender_t(int nb_probes,
                      int probing_rate,
                      const Tins::IPv4Address & dst1,
                      const Tins::IPv4Address & dst2

    ):
            nb_probes{nb_probes},
            probing_rate{probing_rate},
            type1_probe{dst1, 64},
            type2_probe{dst2, 64}
    {

    }

    void start(Tins::PacketSender &sender) {
        // Build the pattern of probing depending of the before/after hop ip addresses.
        std::vector<probe_t<Protocol>> probe_pattern;
        if (before_hop_probe.first){
            probe_pattern.push_back(before_hop_probe.second);
        }
        if (after_hop_probe.first){
            probe_pattern.push_back(after_hop_probe.second);
        }
        probe_pattern.push_back(type1_probe);
        for (int i = 0; i < 8 ; ++i){
            probe_pattern.push_back(type2_probe);
        }



        uint16_t ip_id = 1;
        auto interval = 1000000/probing_rate;
        int probe_sent = 0;

        for (int i = 0;probe_sent < nb_probes; ++ip_id, ++probe_sent, ++i){

            auto & probe_to_send = probe_pattern[i%probe_pattern.size()];
            probe_to_send.id(ip_id);
            probe_to_send.send(sender);
            if (ip_id != nb_probes - 1){
                std::this_thread::sleep_for(std::chrono::microseconds(interval));
            }
            else{
                //Wait for the last packet to get responded
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }

    void set_before_hop_probe(const Tins::IPv4Address & new_before_address, 
                              uint8_t ttl, 
                              uint16_t sport,
                              uint16_t dport
                              ) {
        if constexpr(std::is_same<Protocol, Tins::TCP>::value or std::is_same<Protocol, Tins::UDP>::value) {
            before_hop_probe = std::make_pair(true, probe_t<Protocol>{new_before_address, ttl, sport, dport});
        }
    }

    void set_before_hop_probe(const Tins::IPv4Address & new_before_address,
                              uint16_t sport,
                              uint16_t dport
    ) {
        
        set_before_hop_probe(new_before_address, 64, sport, dport);
    }

    void set_before_hop_probe(const Tins::IPv4Address & new_before_address
    ) {
        before_hop_probe = std::make_pair(true, probe_t<Protocol>{new_before_address, 64});
    }

    void set_after_hop_probe(const Tins::IPv4Address & new_after_address,
                              uint8_t ttl,
                              uint16_t sport,
                              uint16_t dport
    ) {
        if constexpr(std::is_same<Protocol, Tins::TCP>::value or std::is_same<Protocol, Tins::UDP>::value) {
            after_hop_probe = std::make_pair(true, probe_t<Protocol>{new_after_address, ttl, sport, dport});
        }
    }

    void set_after_hop_probe(const Tins::IPv4Address & new_after_address,
                              uint16_t sport,
                              uint16_t dport
    ) {

        set_after_hop_probe(new_after_address, 64, sport, dport);
    }

    void set_after_hop_probe(const Tins::IPv4Address & new_after_address
    ) {
        after_hop_probe = std::make_pair(true, probe_t<Protocol>{new_after_address, 64});
    }
    

private:
    int nb_probes;
    int probing_rate;

    probe_t<Protocol> type1_probe;
    probe_t<Protocol> type2_probe;

    // Optional stuff /IMPLEM TB replaced with std::optional
    std::pair<bool, probe_t<Protocol>> before_hop_probe;
    std::pair<bool, probe_t<Protocol>> after_hop_probe;
};

#endif //ICMPRATELIMITING_RATE_LIMIT_SENDER_T_HPP
