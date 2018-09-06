//
// Created by System Administrator on 29/08/2018.
//

#include <sstream>
#include "../include/probe_infos_t.hpp"

using namespace Tins;
using namespace utils;
probe_infos_t::probe_infos_t(int group_id, int probing_rate, const IP &packet, const IPv4Address & real_target, PDU::PDUType protocol, probing_style_t probing_style, interface_type_t interface_type) :
        m_group_id(group_id),
        m_probing_rate(probing_rate),
        m_packet(packet),
        m_real_target(real_target),
        m_protocol (protocol),
        m_probing_style(probing_style),
        m_interface_type (interface_type)
{

}

const IP &probe_infos_t::get_packet() const {
    return m_packet;
}

probing_style_t probe_infos_t::get_probing_style() const {
    return m_probing_style;
}

PDU::PDUType probe_infos_t::get_protocol() const {
    return m_protocol;
}

const IPv4Address &probe_infos_t::get_real_target() const {
    return m_real_target;
}

int probe_infos_t::get_group_id() const {
    return m_group_id;
}

std::string probe_infos_t::icmp_type_str() const {
    std::string icmp_type;
    if (m_probing_style == probing_style_t::DIRECT){
        if (m_protocol == PDU::PDUType::ICMP){
            icmp_type = "icmp_echo_reply";
        } else {
            icmp_type = "icmp_unreachable";
        }
    } else {
        icmp_type = "icmp_ttl_exceeded";
    }
    return icmp_type;
}

interface_type_t probe_infos_t::get_interface_type() const {
    return m_interface_type;
}

int probe_infos_t::get_probing_rate() const {
    return m_probing_rate;
}

void probe_infos_t::set_probing_rate(int probing_rate) {
    m_probing_rate = probing_rate;
}


std::string to_file_name (const std::vector<probe_infos_t> & alias_test, char separator){
    std::stringstream ss;
    for (int i = 0; i < alias_test.size(); ++i){

        if (i != 0){
            ss << separator;
        }
        ss << alias_test[i].get_real_target();
    }
    return ss.str();
}
