//
// Created by System Administrator on 05/07/2018.
//

#include <unordered_map>
#include <iostream>
#include "../include/rate_limit_analyzer_t.hpp"

using namespace Tins;

void rate_limit_analyzer_t::sort_by_timestamp(std::vector<Packet> & packets){
    std::sort(packets.begin(), packets.end(), [](const Packet & packet1, const Packet & packet2){
        return std::chrono::microseconds(packet1.timestamp()).count() < std::chrono::microseconds(packet2.timestamp()).count();
    });
}

rate_limit_analyzer_t::rate_limit_analyzer_t(const port_ttl_ip_t & port_ip1,
                                             const port_ttl_ip_t & port_ip2) :
        probing_style(probing_style_t::INDIRECT),
        port_ttl_ip1(port_ip1),
        port_ttl_ip2(port_ip2) {

}

rate_limit_analyzer_t::rate_limit_analyzer_t(): probing_style(probing_style_t::DIRECT) {

}

void rate_limit_analyzer_t::set_port_ttl_ip_before(const rate_limit_analyzer_t::port_ttl_ip_t &new_port_ttl_ip_before) {
    port_ttl_ip_before = new_port_ttl_ip_before;
}

void rate_limit_analyzer_t::set_port_ttl_ip_after(const rate_limit_analyzer_t::port_ttl_ip_t &new_port_ttl_ip_after) {
    port_ttl_ip_after = new_port_ttl_ip_after;
}

double rate_limit_analyzer_t::compute_loss_rate(const std::vector<responsive_info_probe_t> & responsive_info_probes) {
    auto total_probes = responsive_info_probes.size();
    auto nb_responsive_probes = 0.0;
    auto nb_unresponsive_probes = 0.0;
    for (const auto & responsive_info_probe: responsive_info_probes){
        if (responsive_info_probe.first){
            ++nb_responsive_probes;
        } else{
            ++nb_unresponsive_probes;
        }
    }

    return nb_unresponsive_probes / total_probes;
}

std::unordered_map<Tins::IPv4Address, double> rate_limit_analyzer_t::compute_loss_rate() {
    std::unordered_map<IPv4Address, double> result;
    std::for_each(packets_per_interface.begin(), packets_per_interface.end(), [](const auto & packets_interface_pair){
        result.insert(std::make_pair(packets_interface_pair->first, compute_loss_rate(packets_interface_pair->second)));
    });
    return result;
}




