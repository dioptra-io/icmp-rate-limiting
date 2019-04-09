//
// Created by System Administrator on 29/08/2018.
//

#include <sstream>
#include "../include/probe_infos_t.hpp"


using namespace Tins;
using namespace utils;
probe_infos_t::probe_infos_t(int group_id, int probing_rate, const IP & packet, const IPv4Address & real_target, PDU::PDUType protocol, probing_style_t probing_style, interface_type_t interface_type) :
        m_group_id(group_id),
        m_probing_rate(probing_rate),
        m_family(PDU::PDUType::IP),
        m_packet4(packet),
        m_real_target4(real_target),
        m_protocol (protocol),
        m_probing_style(probing_style),
        m_interface_type (interface_type)
{

}

probe_infos_t::probe_infos_t(int group_id, int probing_rate, const IPv6 & packet, const IPv6Address & real_target, PDU::PDUType protocol, probing_style_t probing_style, interface_type_t interface_type) :
        m_group_id(group_id),
        m_probing_rate(probing_rate),
        m_family(PDU::PDUType::IPv6),
        m_packet6(packet),
        m_real_target6(real_target),
        m_protocol (protocol),
        m_probing_style(probing_style),
        m_interface_type (interface_type)
{

}

probing_style_t probe_infos_t::get_probing_style() const {
    return m_probing_style;
}

PDU::PDUType probe_infos_t::get_protocol() const {
    return m_protocol;
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

PDU::PDUType probe_infos_t::get_family() const {
    return m_family;
}

const IP &probe_infos_t::get_packet4() const {
    return m_packet4;
}

const IPv6 &probe_infos_t::get_packet6() const {
    return m_packet6;
}

const IPv4Address &probe_infos_t::get_real_target4() const {
    return m_real_target4;
}

const IPv6Address &probe_infos_t::get_real_target6() const {
    return m_real_target6;
}

std::string probe_infos_t::get_real_target() const {
    if (m_family == PDU::PDUType::IP){
        return m_real_target4.to_string();
    } else if (m_family == PDU::PDUType::IPv6){
        return m_real_target6.to_string();
    }
    return "";
}


std::string to_file_name (const std::vector<probe_infos_t> & alias_test, char separator){
    std::stringstream ss;

    // To avoid to reach the limit of file_name, cut the file_name to 2 candidates and 1 witness, even if there are more than
    // 2 candidates
    auto candidates = 0;
    for (std::size_t i = 0; i < alias_test.size(); ++i){

        if (i != 0){
            ss << separator;
        }

        if (alias_test[i].get_interface_type() == interface_type_t::CANDIDATE) {
            if (alias_test[i].get_family() == PDU::PDUType::IP) {
                ss << alias_test[i].get_real_target4();
            } else if (alias_test[i].get_family() == PDU::PDUType::IPv6) {
                ss << alias_test[i].get_real_target6();
            }
            candidates += 1;
            if (candidates == 2){
                break;
            }

        }
    }

    for (std::size_t i = 0; i < alias_test.size(); ++i){
        if (alias_test[i].get_interface_type() == interface_type_t::WITNESS){
            ss << separator;
            if (alias_test[i].get_family() == PDU::PDUType::IP){
                ss << alias_test[i].get_real_target4();
            } else if (alias_test[i].get_family() == PDU::PDUType::IPv6){
                ss << alias_test[i].get_real_target6();
            }
            break;
        }
    }


    return ss.str();
}
