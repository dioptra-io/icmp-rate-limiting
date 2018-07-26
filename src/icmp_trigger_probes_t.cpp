//
// Created by System Administrator on 25/07/2018.
//

#include <sstream>
#include <icmp_trigger_probes_t.hpp>

using namespace Tins;

icmp_trigger_probes_t::icmp_trigger_probes_t(const Tins::IP &icmp_ttl_exceeded, const Tins::IP &icmp_dst_unreachable,
                                           const Tins::IP &icmp_echo_reply) : icmp_ttl_exceeded(icmp_ttl_exceeded),
                                                                              icmp_dst_unreachable(
                                                                                      icmp_dst_unreachable),
                                                                              icmp_echo_reply(icmp_echo_reply) {}

std::string icmp_trigger_probes_t::test_address() const {
    return icmp_echo_reply.dst_addr().to_string();
}

const IP &icmp_trigger_probes_t::get_icmp_ttl_exceeded() const {
    return icmp_ttl_exceeded;
}

const IP &icmp_trigger_probes_t::get_icmp_dst_unreachable() const {
    return icmp_dst_unreachable;
}

const IP &icmp_trigger_probes_t::get_icmp_echo_reply() const {
    return icmp_echo_reply;
}


bool operator == (const icmp_trigger_probes_t & triplet1, const icmp_trigger_probes_t & triplet2 ){
    return triplet1.icmp_echo_reply.dst_addr() == triplet2.icmp_echo_reply.dst_addr();
}

IP build_icmp_triggering_probe(const IPv4Address & dst_ip, const IPv4Address & src_ip,  uint16_t sport, uint16_t dport, uint8_t ttl, ICMP::Flags icmp_type){
    IP icmp_triggering_probe;
    if (icmp_type == ICMP::TIME_EXCEEDED or icmp_type == ICMP::DEST_UNREACHABLE){
        icmp_triggering_probe = IP(dst_ip, src_ip)/UDP(dport, sport);
    } else if (icmp_type == ICMP::ECHO_REPLY){
        icmp_triggering_probe = IP(dst_ip, src_ip) / ICMP();
    }
    if (icmp_type == ICMP::TIME_EXCEEDED){
        icmp_triggering_probe.ttl(ttl);
    } else {
        icmp_triggering_probe.ttl(64);
    }
    return icmp_triggering_probe;
}

std::string to_string(const std::vector<icmp_trigger_probes_t> & alias_test){
    std::stringstream ss;
    ss << "[";
    for (int i = 0; i < alias_test.size(); ++i){
        if (i != 0){
            ss << ", ";
        }
        ss << alias_test[i].test_address();
    }
    ss << "]";

    return ss.str();
}

std::string to_file_name (const std::vector<icmp_trigger_probes_t> & alias_test, char separator){
    std::stringstream ss;
    for (int i = 0; i < alias_test.size(); ++i){

        if (i != 0){
            ss << separator;
        }
        ss << alias_test[i].test_address();
    }
    return ss.str();
}