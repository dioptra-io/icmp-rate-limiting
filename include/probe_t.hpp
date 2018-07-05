//
// Created by System Administrator on 04/07/2018.
//

#ifndef ICMPRATELIMITING_PROBE_T_HPP
#define ICMPRATELIMITING_PROBE_T_HPP

#include <cstdint>
#include <tins/tins.h>


template<typename P>
class probe_t{
public:

    probe_t() = default;
    /**
     * ICMP probing
     * @param dst
     * @param ttl
     * @param payload
     */
    probe_t(const Tins::IPv4Address & dst, uint8_t ttl, const std::string & payload): inner_probe(Tins::IP(dst)/P()/Tins::RawPDU(payload)){
        inner_probe.ttl(ttl);
    }

    probe_t(const Tins::IPv4Address & dst, uint8_t ttl): inner_probe(Tins::IP(dst)/P()){
        inner_probe.ttl(ttl);
    }

    /**
     * UDP or TCP probing
     * @param dst
     * @param ttl
     * @param sport
     * @param dport
     */
    probe_t(const Tins::IPv4Address & dst, uint8_t ttl, uint16_t sport, uint16_t dport) : inner_probe(Tins::IP(dst)/P(dport, sport)){
        inner_probe.ttl(ttl);
    }

    void send(Tins::PacketSender & sender){
        sender.send(inner_probe);
    }

    void id(uint16_t id){
        auto icmp = inner_probe.find_pdu<Tins::ICMP>();
        if (icmp == NULL){
            inner_probe.id(id);
        }
        else{
            icmp->id(id);
        }
    }
private:
    Tins::IP inner_probe;
};


#endif //ICMPRATELIMITING_PROBE_T_HPP
