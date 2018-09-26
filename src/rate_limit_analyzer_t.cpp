//
// Created by System Administrator on 05/07/2018.
//

#include <unordered_map>
#include <iostream>
#include <chrono>
#include <rate_limit_analyzer_t.hpp>
#include <utils/maths_utils_t.hpp>

using namespace Tins;

using namespace utils;

rate_limit_analyzer_t::rate_limit_analyzer_t(probing_style_t probing_style, PDU::PDUType family) :
        ip_family(family),
        probing_style(probing_style)
{

}

rate_limit_analyzer_t::rate_limit_analyzer_t(probing_style_t probing_style,
                                             const std::unordered_map<Tins::IPv4Address, Tins::IP> & matchers):
        ip_family(PDU::PDUType::IP),
        probing_style(probing_style),
        matchers4(matchers)
{

}

rate_limit_analyzer_t::rate_limit_analyzer_t(probing_style_t probing_style,
                                             const std::unordered_map<IPv6Address, IPv6> & matchers):
        ip_family(PDU::PDUType::IPv6),
        probing_style(probing_style),
        matchers6(matchers) {

}


void rate_limit_analyzer_t::sort_by_timestamp(std::vector<Packet> & packets){
    std::sort(packets.begin(), packets.end(), [](const Packet & packet1, const Packet & packet2){
        return std::chrono::microseconds(packet1.timestamp()).count() < std::chrono::microseconds(packet2.timestamp()).count();
    });
}

double rate_limit_analyzer_t::compute_loss_rate(const std::vector<responsive_info_probe_t> & responsive_info_probes) const{
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

std::unordered_map<Tins::IPv4Address, double> rate_limit_analyzer_t::compute_loss_rate4() {
    std::unordered_map<IPv4Address, double> result;
    std::for_each(packets_per_interface4.begin(), packets_per_interface4.end(), [this, &result](const auto & packets_interface_pair){
        result.insert(std::make_pair(packets_interface_pair.first, this->compute_loss_rate(packets_interface_pair.second)));
    });
    return result;
}

std::unordered_map<Tins::IPv6Address, double> rate_limit_analyzer_t::compute_loss_rate6() {
    std::unordered_map<IPv6Address, double> result;
    std::for_each(packets_per_interface6.begin(), packets_per_interface6.end(), [this, &result](const auto & packets_interface_pair){
        result.insert(std::make_pair(packets_interface_pair.first, this->compute_loss_rate(packets_interface_pair.second)));
    });
    return result;
}



rate_limit_analyzer_t::time_series_t rate_limit_analyzer_t::extract_responsiveness_time_series(const std::vector<responsive_info_probe_t> & packet_serie) {
    time_series_t time_series;

    if (!packet_serie.empty()) {

        bool is_responsive = packet_serie.begin()->first;
        std::chrono::milliseconds start_interval_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::microseconds(packet_serie.begin()->second.timestamp()));
        std::chrono::milliseconds end_time_interval_time;
        auto current_packet_number = 0;
        bool must_flush_last_interval = true;
        for (const auto &packet: packet_serie) {
            if (packet.first == is_responsive) {
                end_time_interval_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::microseconds(packet.second.timestamp()));
                ++current_packet_number;
                must_flush_last_interval = true;
                continue;
            } else {
                // Put the new interval in the time_serie object
                time_series.emplace_back(is_responsive, current_packet_number,
                                         std::make_pair(start_interval_time.count(), end_time_interval_time.count()));
                // Reset the starting interval
                start_interval_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::microseconds(packet.second.timestamp()));
                end_time_interval_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::microseconds(packet.second.timestamp()));
                current_packet_number = 1;
                is_responsive = !is_responsive;
                must_flush_last_interval = false;
            }
        }
        if (must_flush_last_interval) {
            time_series.emplace_back(is_responsive, current_packet_number,
                                     std::make_pair(start_interval_time.count(), end_time_interval_time.count()));
        }
    }
    return time_series;
}

std::unordered_map<IPv4Address, rate_limit_analyzer_t::time_series_t>
rate_limit_analyzer_t::extract_responsiveness_time_series4() {
    std::unordered_map<IPv4Address, rate_limit_analyzer_t::time_series_t> time_series_by_ip;
    std::for_each(packets_per_interface4.begin(), packets_per_interface4.end(), [&time_series_by_ip, this](const auto & packets_per_ip){
        time_series_by_ip.insert(std::make_pair(packets_per_ip.first, this->extract_responsiveness_time_series(packets_per_ip.second)));
    });

    return time_series_by_ip;
}

std::unordered_map<IPv6Address, rate_limit_analyzer_t::time_series_t>
rate_limit_analyzer_t::extract_responsiveness_time_series6() {
    std::unordered_map<IPv6Address, rate_limit_analyzer_t::time_series_t> time_series_by_ip;
    std::for_each(packets_per_interface6.begin(), packets_per_interface6.end(), [&time_series_by_ip, this](const auto & packets_per_ip){
        time_series_by_ip.insert(std::make_pair(packets_per_ip.first, this->extract_responsiveness_time_series(packets_per_ip.second)));
    });

    return time_series_by_ip;
}

void rate_limit_analyzer_t::dump_time_series() {
    auto time_series = extract_responsiveness_time_series4();

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
    auto loss_rates = compute_loss_rate4();
    std::for_each(loss_rates.begin(), loss_rates.end(), [](const auto & pair){
        auto ip = pair.first;
        auto loss_rate = pair.second;
        std::cout << ip << ": " << loss_rate << "\n";
    });
}

rate_limit_estimate_t rate_limit_analyzer_t::compute_mean_stddev(const time_series_t & responsiveness_time_interval) {

    std::vector<double> responsive_token_rate;
    std::vector<double> unresponsive_packets;
    // In ms
    std::vector<double> interval_duration;


    // first pass, compute the token rate
    for (int i = 0; i < responsiveness_time_interval.size(); ++i){

        auto is_responsive = std::get<0>(responsiveness_time_interval[i]);
        auto number_of_packets = std::get<1>(responsiveness_time_interval[i]);
        if (is_responsive){
            responsive_token_rate.emplace_back(number_of_packets);
        }
        if (i%2 == 1){
            // Build an interval of a phase (responsiveness + non responsiveness)
            auto interval = std::get<2>(responsiveness_time_interval[i]);
            auto difference_time = interval.second - interval.first;
            auto previous_interval = std::get<2>(responsiveness_time_interval[i]);
            auto previous_difference_time = previous_interval.second - previous_interval.first;
            interval_duration.emplace_back(difference_time + previous_difference_time);
        }

    }

    // Remove the anomalies.


    auto mean_stddev_token_rate = mean_stddev(responsive_token_rate.begin(), responsive_token_rate.end());



    rate_limit_estimate_t estimation;



    return estimation;
}

void rate_limit_analyzer_t::start(const std::string &pcap_file)  {

    // v4 or v6



    auto build_series4 = [this](Tins::Packet & packet){
        auto pdu = packet.pdu();
        auto icmp = pdu->find_pdu<ICMP>();
        if (icmp == NULL or icmp->type() == Tins::ICMP::Flags::ECHO_REQUEST){
            outgoing_packets.push_back(packet);
        } else {
            icmp_replies.push_back(packet);
        }
        return true;
    };

    auto build_series6 = [this](Tins::Packet & packet){
        auto pdu = packet.pdu();
        auto icmp = pdu->find_pdu<ICMPv6>();
        if (icmp == NULL or icmp->type() == Tins::ICMPv6::Types::ECHO_REQUEST){
            outgoing_packets.push_back(packet);
        } else {
            icmp_replies.push_back(packet);
        }
        return true;
    };

    bool is_v4 = false;
    bool is_v6 = false;
    Tins::FileSniffer sniffer(pcap_file);
    if (ip_family == PDU::PDUType::IP){
        sniffer.sniff_loop(build_series4);
        is_v4 = true;
    } else if (ip_family == PDU::PDUType::IPv6){
        sniffer.sniff_loop(build_series6);
        is_v6 = true;
    }

    // Matches probe with replies and extract responsiveness
    sort_by_timestamp(outgoing_packets);
    // Remove the last packet that had been sent to shut the sniffer.
    outgoing_packets.erase(outgoing_packets.end()-1);
    if (is_v4){
        for(const auto & packet : outgoing_packets){
            auto outgoing_pdu = packet.pdu();
            // Find the IP layer

            auto ip = outgoing_pdu->rfind_pdu<Tins::IP>();

            auto it = std::find_if(icmp_replies.begin(), icmp_replies.end(), [&ip](const Tins::Packet & matching_packet){
                auto pdu = matching_packet.pdu();
                auto icmp = pdu->find_pdu<Tins::ICMP>();
                if (icmp->type() == Tins::ICMP::Flags::ECHO_REPLY){
                    try{
                        // We are in an ICMP direct probing so we match se probes with the icmp id
                        auto icmp_request = ip.find_pdu<ICMP>();
                        if (icmp_request != nullptr){
                            if (icmp->id() == icmp_request->id()){
                                return true;
                            }
                        }

                    } catch (const Tins::malformed_packet & e){
                        std::cerr << e.what() << "\n";
                    }


                } else {
                    // We are in a TCP or UDP probing so match with the probes with the ip id
                    try{
                        const auto &raw_inner_transport = icmp->rfind_pdu<Tins::RawPDU>();
                        auto inner_ip = raw_inner_transport.to<Tins::IP>();
                        if (inner_ip.id() == ip.id()){
                            return true;
                        }
                    } catch (const Tins::malformed_packet & e){
                        std::cerr << e.what() << "\n";
                    }
                }
                return false;
            });
            if (it != icmp_replies.end()){
                auto ip_reply = it->pdu()->template rfind_pdu<Tins::IP>().src_addr();
                // Erase this response.

//                std::cout << "Responsive " << ip_reply << " " <<  std::chrono::microseconds(packet.timestamp()).count() << "\n";
                // Insert the reply in the responsiveness map
                auto ip_key = packets_per_interface4.find(ip_reply);
                if (ip_key == packets_per_interface4.end()) {
                    packets_per_interface4.insert(std::make_pair(ip_reply, std::vector<responsive_info_probe_t>()));
                }
                packets_per_interface4[ip_reply].push_back(std::make_pair(true, packet));

                icmp_replies.erase(it);
            } else {
                Tins::IPv4Address dst_ip;
                if (probing_style == probing_style_t::DIRECT){
                    // Match the ip probe with the destination in case of direct probing
                    dst_ip = ip.dst_addr();
                } else if (probing_style == probing_style_t::INDIRECT){
                    // Match the ip probe with the sport in case of indirect probing
                    for (const auto & matcher : matchers4){
                        if (match_probe(matcher.second, ip)){
                            dst_ip = matcher.first;
                            break;
                        }
                    }

                }

                auto ip_key = packets_per_interface4.find(dst_ip);
                if (ip_key == packets_per_interface4.end()){
                    packets_per_interface4.insert(std::make_pair(dst_ip, std::vector<responsive_info_probe_t>()));
                }
                packets_per_interface4[dst_ip].push_back(std::make_pair(false, packet));
//                std::cout << "Unresponsive " << dst_ip << " " <<  std::chrono::microseconds(packet.timestamp()).count() << "\n";


            }
        }
    }

    else if (is_v6){
        for(const auto & packet : outgoing_packets) {
            auto outgoing_pdu = packet.pdu();
            // Find the IP layer
            auto ip = outgoing_pdu->rfind_pdu<IPv6>();

            auto it = std::find_if(icmp_replies.begin(), icmp_replies.end(), [&ip](const Tins::Packet & matching_packet){
                auto pdu = matching_packet.pdu();
                auto icmp = pdu->find_pdu<Tins::ICMPv6>();
                if (icmp->type() == Tins::ICMPv6::Types::ECHO_REPLY){
                    try{
                        // We are in an ICMP direct probing so we match se probes with the icmp id
                        auto icmp_request = ip.find_pdu<ICMPv6>();
                        if (icmp_request != nullptr){
                            if (icmp->identifier() == icmp_request->identifier()){
                                return true;
                            }
                        }

                    } catch (const Tins::malformed_packet & e){
                        std::cerr << e.what() << "\n";
                    }


                } else {
                    // We are in a TCP or UDP probing so match with the probes with the ip id
                    //TODO
                }
                return false;
            });

            if (it != icmp_replies.end()){
                auto ip_reply = it->pdu()->template rfind_pdu<IPv6>().src_addr();
                // Erase this response.

//                std::cout << "Responsive " << ip_reply << " " <<  std::chrono::microseconds(packet.timestamp()).count() << "\n";
                // Insert the reply in the responsiveness map
                auto ip_key = packets_per_interface6.find(ip_reply);
                if (ip_key == packets_per_interface6.end()) {
                    packets_per_interface6.insert(std::make_pair(ip_reply, std::vector<responsive_info_probe_t>()));
                }
                packets_per_interface6[ip_reply].push_back(std::make_pair(true, packet));

                icmp_replies.erase(it);
            } else {
                Tins::IPv6Address dst_ip;
                if (probing_style == probing_style_t::DIRECT){
                    // Match the ip probe with the destination in case of direct probing
                    dst_ip = ip.dst_addr();
                }
                else if (probing_style == probing_style_t::INDIRECT){
                    //TODO v6 does not handle yet indirect
//                    // Match the ip probe with the sport in case of indirect probing
//                    for (const auto & matcher : matchers6){
//                        if (match_probe(matcher.second, ip)){
//                            dst_ip = matcher.first;
//                            break;
//                        }
//                    }

                }

                auto ip_key = packets_per_interface6.find(dst_ip);
                if (ip_key == packets_per_interface6.end()){
                    packets_per_interface6.insert(std::make_pair(dst_ip, std::vector<responsive_info_probe_t>()));
                }
                packets_per_interface6[dst_ip].push_back(std::make_pair(false, packet));
//                std::cout << "Unresponsive " << dst_ip << " " <<  std::chrono::microseconds(packet.timestamp()).count() << "\n";


            }

        }
    }

}

bool rate_limit_analyzer_t::match_probe(const Tins::IP & match, const Tins::IP & probe) {
    const UDP* match_transport_udp = match.find_pdu<UDP>();
    const TCP* match_transport_tcp = nullptr;
    uint16_t match_sport = 0;
    auto match_ttl = match.ttl();
    if (match_transport_udp == nullptr){
        match_transport_tcp = match.find_pdu<TCP>();
        if (match_transport_tcp != nullptr){
            match_sport = match_transport_tcp->sport();
        }
    } else {
        match_sport = match_transport_udp->sport();
    }


    const UDP* transport_udp = probe.find_pdu<UDP>();
    const TCP* transport_tcp = nullptr;
    uint16_t sport = 0;
    auto ttl = probe.ttl();
    if (transport_udp == nullptr){
        transport_tcp = probe.find_pdu<TCP>();
        if(transport_tcp!=nullptr){
            sport = transport_tcp->sport();
        }
    }
    else{
        sport = transport_udp->sport();
    }
    return sport == match_sport and ttl == match_ttl;
}

probing_style_t rate_limit_analyzer_t::get_probing_style() const {
    return probing_style;
}

gilbert_elliot_t
rate_limit_analyzer_t::compute_loss_model(const std::vector<responsive_info_probe_t> & responsive_info_probes) const {
    gilbert_elliot_t loss_model;

    // loss model : state 0 is responsive
    //              state 1 is unresponsive

    std::vector<std::vector<int>> n_transitions(2, std::vector<int>(2, 0));
    if (!responsive_info_probes.empty()){
        bool previous_state = responsive_info_probes.begin()->first;
        for (auto i = 1; i < responsive_info_probes.size(); ++i){
            if (responsive_info_probes[i].first == previous_state){
                if (previous_state){
                    n_transitions[0][0] += 1;
                } else {
                    n_transitions[1][1] += 1;
                }
            } else {
                if (previous_state){
                    n_transitions[0][1] += 1;
                } else {
                    n_transitions[1][0] += 1;
                }
                previous_state = !previous_state;
            }
        }

        for (int i = 0; i < n_transitions.size(); ++i){

            auto total_transition_state = std::accumulate(n_transitions[i].begin(), n_transitions[i].end(), 0);

            for(int j = 0; j < n_transitions[i].size(); ++j){
                loss_model.transition(i, j, static_cast<double>(n_transitions[i][j])/ total_transition_state);
            }
        }
    }


    return loss_model;
}

void rate_limit_analyzer_t::dump_gilbert_eliot() {

    std::for_each(packets_per_interface4.begin(), packets_per_interface4.end(), [this](const auto & packets_interface){
        std::cout << packets_interface.first << "\n";
        gilbert_elliot_t loss_model = this->compute_loss_model(packets_interface.second);
        this->dump_transition_matrix(loss_model);
    });
}

void rate_limit_analyzer_t::dump_transition_matrix(const gilbert_elliot_t &loss_model) {
    std::cout << "P(R, R) = " << loss_model.transition(0, 0) << "\n";
    std::cout << "P(R, U) = " << loss_model.transition(0, 1) << "\n";
    std::cout << "P(U, R) = " << loss_model.transition(1, 0) << "\n";
    std::cout << "P(U, U) = " << loss_model.transition(1, 1) << "\n";
}

rate_limit_analyzer_t::time_series_t rate_limit_analyzer_t::get_responsiveness(const Tins::IPv4Address & address) {
    return extract_responsiveness_time_series(packets_per_interface4[address]);
}

double rate_limit_analyzer_t::compute_loss_rate(const IPv4Address & ip) const {
    return compute_loss_rate(packets_per_interface4.at(ip));
}

double rate_limit_analyzer_t::compute_loss_rate(const IPv6Address & ip) const {
    return compute_loss_rate(packets_per_interface6.at(ip));
}

std::vector<responsive_info_probe_t> rate_limit_analyzer_t::get_raw_packets4(const IPv4Address &ip) const {
    try {
        return packets_per_interface4.at(ip);
    } catch (const std::out_of_range & e){
        std::cerr << "Keys found:\n";
        for (const auto & pair : packets_per_interface4){
            std::cerr << pair.first << "\n";
        }
        std::cerr << "Was looking for key " << ip << "\n";
        std::cerr << "Error: May be network dynamics.\n";
    }
    return std::vector<responsive_info_probe_t>();
}

std::vector<responsive_info_probe_t> rate_limit_analyzer_t::get_raw_packets6(const IPv6Address &ip) const {
    try {
        return packets_per_interface6.at(ip);
    } catch (const std::out_of_range & e){
        std::cerr << "Keys found:\n";
        for (const auto & pair : packets_per_interface6){
            std::cerr << pair.first << "\n";
        }
        std::cerr << "Was looking for key " << ip << "\n";
        std::cerr << "Error: May be network dynamics.\n";
    }
    return std::vector<responsive_info_probe_t>();
}

gilbert_elliot_t rate_limit_analyzer_t::compute_loss_model(const Tins::IPv4Address &address) const{
    return compute_loss_model(packets_per_interface4.at(address));
}

packet_interval_t rate_limit_analyzer_t::compute_icmp_triggering_rate(
        const std::vector<responsive_info_probe_t> &data) const {
    double global_loss_rate_treshold = 0.12;
    double loss_rate_treshold = 0.2;
    int interval_length = 100;

    int triggering_loss_rate = -1;

    auto global_loss_rate = compute_loss_rate(data);
    if (global_loss_rate > global_loss_rate_treshold) {
        for (int i = 0; i < data.size() - interval_length; i += interval_length / 2) {
            auto last_index = data.begin();
            if ((i + 2 * interval_length) < data.size()) {
                last_index = data.begin() + i + interval_length;
            } else {
                break;
            }

            std::vector<responsive_info_probe_t> responsiveness_interval(data.begin() + i, last_index);
            auto loss_rate_interval = compute_loss_rate(responsiveness_interval);

            if (loss_rate_interval > loss_rate_treshold) {
                triggering_loss_rate = i;
                break;
            }
        }
    }
    if (triggering_loss_rate == -1){
        return std::make_pair(triggering_loss_rate, triggering_loss_rate);
    }
    return std::make_pair(triggering_loss_rate, triggering_loss_rate + interval_length);
}

std::unordered_map<IPv4Address, packet_interval_t>
rate_limit_analyzer_t::compute_icmp_triggering_rate4() const {
    std::unordered_map<IPv4Address, packet_interval_t> icmp_triggering_rate;
    for (const auto & responsiveness_ip : packets_per_interface4){
        auto triggering_rate = compute_icmp_triggering_rate(responsiveness_ip.second);
        icmp_triggering_rate[responsiveness_ip.first] = triggering_rate;
    }
    return icmp_triggering_rate;
}

std::unordered_map<IPv6Address, packet_interval_t>
rate_limit_analyzer_t::compute_icmp_triggering_rate6() const {
    std::unordered_map<IPv6Address, packet_interval_t> icmp_triggering_rate;
    for (const auto & responsiveness_ip : packets_per_interface6){
        auto triggering_rate = compute_icmp_triggering_rate(responsiveness_ip.second);
        icmp_triggering_rate[responsiveness_ip.first] = triggering_rate;
    }
    return icmp_triggering_rate;
}






