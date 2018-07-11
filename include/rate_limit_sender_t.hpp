//
// Created by System Administrator on 04/07/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_SENDER_T_HPP
#define ICMPRATELIMITING_RATE_LIMIT_SENDER_T_HPP

#include <tins/tins.h>
#include <unordered_map>
#include "probe_t.hpp"

class rate_limit_sender_t{
public:


    rate_limit_sender_t(int nb_probes,
                        int probing_rate,
                        const Tins::NetworkInterface & iface,
                        const std::vector<Tins::IP> & candidates,
                        const std::vector<Tins::IP> & options_ip);

    rate_limit_sender_t(const rate_limit_sender_t & copy_rate_limit_sender);

    rate_limit_sender_t reverse() const;

    void start();



private:
    std::vector<Tins::IP> build_probing_pattern(int N);

    int nb_probes;
    int probing_rate;

    uint8_t protocol;

    Tins::NetworkInterface sending_iface;
    Tins::PacketSender sender;
    std::vector<Tins::IP> candidates;
    std::vector<Tins::IP> options_ip;

};

#endif //ICMPRATELIMITING_RATE_LIMIT_SENDER_T_HPP
