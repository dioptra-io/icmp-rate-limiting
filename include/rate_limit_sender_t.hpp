//
// Created by System Administrator on 04/07/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_SENDER_T_HPP
#define ICMPRATELIMITING_RATE_LIMIT_SENDER_T_HPP

#include <tins/tins.h>
#include <unordered_map>
#include <probe_infos_t.hpp>

class rate_limit_sender_t{
public:


    rate_limit_sender_t(int nb_probes,
                        int probing_rate,
                        const Tins::NetworkInterface & iface,
                        const std::vector<probe_infos_t> & candidates);

    rate_limit_sender_t(const rate_limit_sender_t & copy_rate_limit_sender);

    void start();

private:
    std::vector<Tins::IP> build_probing_pattern4(int N);
    std::vector<Tins::IPv6> build_probing_pattern6(int N);

    int nb_probes;
    int probing_rate;

    Tins::NetworkInterface sending_iface;
    std::vector<probe_infos_t> candidates;
//    sender_t sender;
    Tins::PacketSender sender;

};

#endif //ICMPRATELIMITING_RATE_LIMIT_SENDER_T_HPP
