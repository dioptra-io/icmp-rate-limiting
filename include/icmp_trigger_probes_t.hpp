//
// Created by System Administrator on 25/07/2018.
//

#ifndef ICMPRATELIMITING_ICMP_TRIGGERING_PROBE_T_HPP
#define ICMPRATELIMITING_ICMP_TRIGGERING_PROBE_T_HPP

#include <tins/tins.h>

class icmp_trigger_probes_t {
public:
    icmp_trigger_probes_t(const Tins::IP &icmp_ttl_exceeded, const Tins::IP &icmp_dst_unreachable,
                         const Tins::IP &icmp_echo_reply);

    std::string test_address() const;

    const Tins::IP &get_icmp_ttl_exceeded() const;

    const Tins::IP &get_icmp_dst_unreachable() const;

    const Tins::IP &get_icmp_echo_reply() const;

    friend bool operator == (const icmp_trigger_probes_t & triplet1, const icmp_trigger_probes_t & triplet2 );

private:
    Tins::IP icmp_ttl_exceeded;
    Tins::IP icmp_dst_unreachable;
    Tins::IP icmp_echo_reply;
};



Tins::IP build_icmp_triggering_probe(const Tins::IPv4Address & dst_ip, const Tins::IPv4Address & src_ip,
                                     uint16_t sport, uint16_t dport,
                                     uint8_t ttl,
                                     Tins::ICMP::Flags icmp_type);

std::string to_string(const std::vector<icmp_trigger_probes_t> & alias_test);
std::string to_file_name (const std::vector<icmp_trigger_probes_t> & alias_test, char separator);
#endif //ICMPRATELIMITING_ICMP_TRIGGERING_PROBE_T_HPP
