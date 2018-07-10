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
    std::for_each(packets_per_interface.begin(), packets_per_interface.end(), [this, &result](const auto & packets_interface_pair){
        result.insert(std::make_pair(packets_interface_pair.first, compute_loss_rate(packets_interface_pair.second)));
    });
    return result;
}


rate_limit_analyzer_t::time_series_t rate_limit_analyzer_t::extract_responsiveness_time_series(const std::vector<responsive_info_probe_t> & packet_serie) {
    time_series_t time_series;

    bool is_responsive = packet_serie.begin()->first;
    std::chrono::microseconds start_interval_time = packet_serie.begin()->second.timestamp();
    std::chrono::microseconds end_time_interval_time;
    auto current_packet_number = 0;
    bool must_flush_last_interval = true;
    for (const auto & packet: packet_serie){
        if (packet.first == is_responsive){
            end_time_interval_time = packet.second.timestamp();
            ++current_packet_number;
            must_flush_last_interval = true;
            continue;
        } else {
            // Put the new interval in the time_serie object
            time_series.emplace_back(is_responsive, current_packet_number,std::make_pair(start_interval_time.count(), end_time_interval_time.count()));
            // Reset the starting interval
            start_interval_time = packet.second.timestamp();
            end_time_interval_time = packet.second.timestamp();
            current_packet_number = 1;
            is_responsive = !is_responsive;
            must_flush_last_interval = false;
        }
    }
    if (must_flush_last_interval){
        time_series.emplace_back(is_responsive, current_packet_number,std::make_pair(start_interval_time.count(), end_time_interval_time.count()));
    }

    return time_series;
}

std::unordered_map<IPv4Address, rate_limit_analyzer_t::time_series_t>
rate_limit_analyzer_t::extract_responsiveness_time_series() {
    std::unordered_map<IPv4Address, rate_limit_analyzer_t::time_series_t> time_series_by_ip;
    std::for_each(packets_per_interface.begin(), packets_per_interface.end(), [&time_series_by_ip, this](const auto & packets_per_ip){
        time_series_by_ip.insert(std::make_pair(packets_per_ip.first, extract_responsiveness_time_series(packets_per_ip.second)));
    });

    return time_series_by_ip;
}

void rate_limit_analyzer_t::dump_time_series() {
    auto time_series = extract_responsiveness_time_series();

    std::for_each(time_series.begin(), time_series.end(), [](const auto & time_series_ip){
       std::cout << time_series_ip.first << "\n";
       auto responsiveness_ip_time_intervals = time_series_ip.second;
       std::for_each(responsiveness_ip_time_intervals.begin(), responsiveness_ip_time_intervals.end(),
                     [](const auto & responsiveness_time_interval){
           std::string is_responsive = std::get<0>(responsiveness_time_interval)? "Responsive" : "Unresponsive";
           auto number_of_packets = std::get<1>(responsiveness_time_interval);
           auto interval = std::get<2>(responsiveness_time_interval);
           auto difference_time = interval.second - interval.first;
           std::cout << is_responsive << ", " << number_of_packets << ", " << difference_time << " ms\n";
       });

    });

}

void rate_limit_analyzer_t::dump_loss_rate() {
    std::cout << "Loss rates:" << "\n";
    auto loss_rates = compute_loss_rate();
    std::for_each(loss_rates.begin(), loss_rates.end(), [](const auto & pair){
        auto ip = pair.first;
        auto loss_rate = pair.second;
        std::cout << ip << ": " << loss_rate << "\n";
    });
}




