//
// Created by System Administrator on 05/07/2018.
//

#include <unordered_map>
#include <iostream>
#include <chrono>
#include <rate_limit_analyzer_t.hpp>
#include <utils/maths_utils_t.hpp>
#include <sstream>
#include <cmath>


#include <RInside.h>                    // for the embedded R via RInside


using namespace Tins;

using namespace utils;

namespace{
// Create the R context
    RInside R_context;
// Load R libraries
    auto load_R_libraries = std::string("library(changepoint);"
                                        "library(changepoint.np);");

    bool already_loaded = false;
    struct compare_icmp_packet{
        bool operator() (const Packet & packet1, const Packet & packet2) const {

            auto icmp1 = packet1.pdu()->template find_pdu<ICMP>();
            auto icmp2 = packet2.pdu()->template find_pdu<ICMP>();

            auto icmp61 = packet1.pdu()->template find_pdu<ICMPv6>();
            auto icmp62 = packet1.pdu()->template find_pdu<ICMPv6>();


            if (icmp1 != nullptr && icmp2 != nullptr){
                return this->operator()(*icmp1, *icmp2);
            }
            else if (icmp61 != nullptr && icmp2 != nullptr){
                return this->operator()(*icmp2, *icmp61);
            } else if (icmp1 != nullptr && icmp62 != nullptr){
                return this->operator()(*icmp1, *icmp62);
            } else if (icmp61 != nullptr && icmp62 != nullptr){
                return this->operator()(*icmp61, *icmp62);
            }
            std::cerr << "Not comparing ICMP packets\n";
            return false;
        }

        bool operator()(const ICMP & icmp1, const ICMP & icmp2 ) const {
            if (icmp1.id() != icmp2.id()){
                return icmp1.id() < icmp2.id();
            } else {
                return icmp1.sequence() < icmp2.sequence();
            }
        }

        bool operator()(const ICMP & icmp1, const ICMPv6 & icmp2 ) const {
            if (icmp1.id() != icmp2.identifier()){
                return icmp1.id() < icmp2.identifier();
            } else {
                return icmp1.sequence() < icmp2.sequence();
            }
        }

        bool operator()(const ICMPv6 & icmp1, const ICMPv6 & icmp2 ) const {
            if (icmp1.identifier() != icmp2.identifier()){
                return icmp1.identifier() < icmp2.identifier();
            } else {
                return icmp1.sequence() < icmp2.sequence();
            }
        }


    };
}


rate_limit_analyzer_t::rate_limit_analyzer_t() {
    // Default constructor
}


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

rate_limit_analyzer_t::rate_limit_analyzer_t(utils::probing_style_t probing_style,
                                             const std::unordered_map<Tins::IPv4Address, Tins::IP> &matchers4,
                                             const std::unordered_map<Tins::IPv6Address, Tins::IPv6> &matchers6):
    probing_style(probing_style),
    matchers4(matchers4),
    matchers6(matchers6)
{

}

void rate_limit_analyzer_t::sort_by_timestamp(std::vector<Packet> & packets){
    std::sort(packets.begin(), packets.end(), [](const Packet & packet1, const Packet & packet2){
        return std::chrono::microseconds(packet1.timestamp()).count() < std::chrono::microseconds(packet2.timestamp()).count();
    });
}

double rate_limit_analyzer_t::compute_loss_rate(const std::vector<responsive_info_probe_t> & responsive_info_probes) const{
    auto total_probes = responsive_info_probes.size();
    if (total_probes == 0){
        return 1;
    }
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

std::unordered_map<std::string, double> rate_limit_analyzer_t::compute_loss_rate() {
    std::unordered_map<std::string, double> result;
    std::for_each(packets_per_interface.begin(), packets_per_interface.end(), [this, &result](const auto & packets_interface_pair){
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

std::unordered_map<std::string, rate_limit_analyzer_t::time_series_t>
rate_limit_analyzer_t::extract_responsiveness_time_series() {
    std::unordered_map<std::string, rate_limit_analyzer_t::time_series_t> time_series_by_ip;
    std::for_each(packets_per_interface.begin(), packets_per_interface.end(), [&time_series_by_ip, this](const auto & packets_per_ip){
        time_series_by_ip.insert(std::make_pair(packets_per_ip.first, this->extract_responsiveness_time_series(packets_per_ip.second)));
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

//    auto src_address4 = NetworkInterface::default_interface().ipv4_address();
    IPv4Address src_address4;
    IPv6Address src_address6;
    auto build_series = [this, &src_address4, &src_address6](Tins::Packet & packet){
        bool is_v4_packet = false;
        bool is_v6_packet = false;
        auto pdu = packet.pdu();
        auto ip = pdu->find_pdu<IP>();
        auto ipv6 = pdu->find_pdu<IPv6>();
        if (ip != nullptr){
            is_v4_packet = true;
        }
        if (ipv6 != nullptr){
            is_v6_packet = true;
        }
        if (is_v4_packet){
            auto icmp = pdu->find_pdu<ICMP>();
            if (src_address4 == IPv4Address()){
                if (icmp != nullptr && icmp->type() == ICMP::Flags ::ECHO_REQUEST){
                    src_address4 = ip->src_addr();
                }
            }

            if (ip->src_addr() == src_address4){
                // This packet was destinated to another address
                auto it = this->matchers4.find(ip->dst_addr());
                if (it == this->matchers4.end()){
                    // Do nothing
                    return true;
                }
            }

            // This packet was from another address
            if (ip->dst_addr() == src_address4){
                auto it = this->matchers4.find(ip->src_addr());
                if (it == this->matchers4.end()){
                    // Do nothing
                    return true;
                }
            }



            if (icmp!= nullptr && icmp->type() == ICMP::Flags::ECHO_REQUEST){
                outgoing_packets.push_back(packet);
            } else {
                auto id_seq_key = std::make_pair(icmp->id(), icmp->sequence());
                if (match_icmp_replies.find(id_seq_key) == match_icmp_replies.end()){
                    match_icmp_replies[id_seq_key] = std::vector<Packet>();

                }
                match_icmp_replies[id_seq_key].push_back(packet);
                icmp_replies.push_back(packet);
            }
        }
        else if (is_v6_packet){
            auto icmpv6 = pdu->find_pdu<ICMPv6>();
            if (src_address6 == IPv6Address()){
                if (icmpv6 != nullptr && icmpv6->type() == ICMPv6::Types::ECHO_REQUEST){
                    src_address6 = ipv6->src_addr();
                }
            }


            if (ipv6->src_addr() == src_address6){
                // This packet was destinated to another address
                auto it = this->matchers6.find(ipv6->dst_addr());
                if (it == this->matchers6.end()){
                    // Do nothing
                    return true;
                }
            }

            // This packet was from another address
            if (ipv6->dst_addr() == src_address6){
                auto it = this->matchers6.find(ipv6->src_addr());
                if (it == this->matchers6.end()){
                    // Do nothing
                    return true;
                }
            }

            if (icmpv6 != nullptr && icmpv6->type() == ICMPv6::Types ::ECHO_REQUEST){
                outgoing_packets.push_back(packet);
            } else if (icmpv6 != nullptr && icmpv6->type() == ICMPv6::Types ::ECHO_REPLY) {
                auto id_seq_key = std::make_pair(icmpv6->identifier(), icmpv6->sequence());
                if (match_icmp_replies.find(id_seq_key) == match_icmp_replies.end()){
                    match_icmp_replies[id_seq_key] = std::vector<Packet>();

                }
                match_icmp_replies[id_seq_key].push_back(packet);
                icmp_replies.push_back(packet);

            }
        }

        return true;
    };

    Tins::FileSniffer sniffer(pcap_file);
    sniffer.sniff_loop(build_series);

    std::cout << "Read " << outgoing_packets.size() << " ICMP(v6) packets outgoing\n";
    auto n_replies = 0;
    for (const auto & replies : match_icmp_replies){
        n_replies += replies.second.size();
    }
    std::cout << "Read " << n_replies << " ICMP(v6) packets replies\n";
    // initialize packets to empty list
    for (const auto & matcher : matchers4){
        packets_per_interface.insert(std::make_pair(matcher.first.to_string(), std::vector<responsive_info_probe_t>()));
    }
    for (const auto & matcher : matchers6){
        packets_per_interface.insert(std::make_pair(matcher.first.to_string(), std::vector<responsive_info_probe_t>()));
    }
    // Matches probe with replies and extract responsiveness
    sort_by_timestamp(outgoing_packets);

    for (const auto & packet: outgoing_packets){
        auto outgoing_pdu = packet.pdu();
        auto ip = outgoing_pdu->find_pdu<IP>();
        auto ip6 = outgoing_pdu->find_pdu<IPv6>();

        if (ip != nullptr){
            auto icmp = ip->find_pdu<ICMP>();
            auto id_seq_key = std::make_pair(icmp->id(), icmp->sequence());


            //DEBUG
//            if (pcap_file.find("DPR") != std::string::npos) {
//                std::cout << id_seq_key.first << ","<< id_seq_key.second << "," << packet.timestamp().microseconds() << "\n";
//            }



            auto it = match_icmp_replies.find(id_seq_key);
            if (it != match_icmp_replies.end()) {
                auto & icmp_replies = it->second;

                auto ip_reply = icmp_replies[0].pdu()->template rfind_pdu<Tins::IP>().src_addr();
                // Erase this response.
                auto destination = ip->dst_addr();
                if (destination != ip_reply){
                    continue;
                }
//                std::cout << "Responsive " << ip_reply << " " <<  std::chrono::microseconds(packet.timestamp()).count() << "\n";
                // Insert the reply in the responsiveness map
                auto ip_key = packets_per_interface.find(ip_reply.to_string());
                if (ip_key == packets_per_interface.end()) {
                    packets_per_interface.insert(std::make_pair(ip_reply.to_string(), std::vector<responsive_info_probe_t>()));
                }
                packets_per_interface[ip_reply.to_string()].push_back(std::make_pair(true, packet));
                icmp_replies.erase(it->second.begin());
                if (icmp_replies.empty()){
                    match_icmp_replies.erase(it);
                }
            }
            else if (it == match_icmp_replies.end()) {
                if (icmp->type() == ICMP::Flags::ECHO_REQUEST){
                    IPv4Address dst_ip;
                    if (probing_style == probing_style_t::DIRECT){
                        // Match the ip probe with the destination in case of direct probing
                        dst_ip = ip->dst_addr();
                    } else if (probing_style == probing_style_t::INDIRECT){

                    }

                    auto ip_key = packets_per_interface.find(dst_ip.to_string());
                    if (ip_key == packets_per_interface.end()){
                        packets_per_interface.insert(std::make_pair(dst_ip.to_string(), std::vector<responsive_info_probe_t>()));
                    }
                    packets_per_interface[dst_ip.to_string()].push_back(std::make_pair(false, packet));
                } else {
                    std::cerr << "Captured another type of ICMP reply\n";
                }

            }
        }

        if (ip6 != nullptr) {

            auto icmpv6 = ip6->find_pdu<ICMPv6>();
            auto id_seq_key = std::make_pair(icmpv6->identifier(), icmpv6->sequence());
            auto it = match_icmp_replies.find(id_seq_key);
            if (it != match_icmp_replies.end()) {
                auto & icmp_replies = it->second;

                auto ip_reply = icmp_replies[0].pdu()->template rfind_pdu<Tins::IPv6>().src_addr();
                // Erase this response.
                auto destination = ip6->dst_addr();
                if (destination != ip_reply){
                    continue;
                }
//                std::cout << "Responsive " << ip_reply << " " <<  std::chrono::microseconds(packet.timestamp()).count() << "\n";
                // Insert the reply in the responsiveness map
                auto ip_key = packets_per_interface.find(ip_reply.to_string());
                if (ip_key == packets_per_interface.end()) {
                    packets_per_interface.insert(std::make_pair(ip_reply.to_string(), std::vector<responsive_info_probe_t>()));
                }
                packets_per_interface[ip_reply.to_string()].push_back(std::make_pair(true, packet));
                icmp_replies.erase(it->second.begin());
                if (icmp_replies.empty()){
                    match_icmp_replies.erase(it);
                }
            }
            else if (it == match_icmp_replies.end()) {
                if (icmpv6->type() == ICMPv6::Types ::ECHO_REQUEST){
                    IPv6Address dst_ip;
                    if (probing_style == probing_style_t::DIRECT){
                        // Match the ip probe with the destination in case of direct probing
                        dst_ip = ip6->dst_addr();
                    } else if (probing_style == probing_style_t::INDIRECT){

                    }

                    auto ip_key = packets_per_interface.find(dst_ip.to_string());
                    if (ip_key == packets_per_interface.end()){
                        packets_per_interface.insert(std::make_pair(dst_ip.to_string(), std::vector<responsive_info_probe_t>()));
                    }
                    packets_per_interface[dst_ip.to_string()].push_back(std::make_pair(false, packet));
                } else {
                    std::cerr << "Captured another type of ICMP reply\n";
                }

            }
        }
    }

    return;
    // Sort the replies by icmp sequence so we can perform a binary search on the icmp replies
    std::sort(icmp_replies.begin(), icmp_replies.end(), compare_icmp_packet{});


    // Remove the last packet that had been sent to shut the sniffer.
    if (!outgoing_packets.empty()){
        outgoing_packets.erase(outgoing_packets.end()-1);
    }
    for(auto & packet : outgoing_packets){
        auto outgoing_pdu = packet.pdu();
        // Find the IP layer

        auto ip = outgoing_pdu->find_pdu<IP>();
        auto ip6 = outgoing_pdu->find_pdu<IPv6>();

        auto range = std::equal_range(icmp_replies.begin(), icmp_replies.end(), packet, compare_icmp_packet());
        auto dist = std::distance(range.first, range.second);
        if (ip != nullptr){

            // Find the matching reply if existing.
            auto it = std::find_if(range.first, range.second,
                                   [&ip](const Tins::Packet & matching_packet){


                                       auto pdu = matching_packet.pdu();
                                       auto reply_ip = pdu->find_pdu<IP>();
                                       auto icmp = pdu->find_pdu<ICMP>();

                                       // We assume direct probing so check only the source

                                       // Check first the destination
                                       auto destination = ip->dst_addr();
                                       if (destination != reply_ip->src_addr()){
                                           return false;
                                       }

                                       if (icmp->type() == Tins::ICMP::Flags::ECHO_REPLY){
                                           try{
                                               // We are in an ICMP direct probing so we match se probes with the icmp sequence number
                                               auto icmp_request = ip->find_pdu<ICMP>();
                                               if (icmp_request != nullptr){
                                                   if (icmp->sequence() == icmp_request->sequence() && icmp->id() == icmp_request->id()){
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
                                               if (inner_ip.id() == ip->id()){
                                                   return true;
                                               }
                                           } catch (const Tins::malformed_packet & e){
                                               std::cerr << e.what() << "\n";
                                           }
                                       }
                                       return false;
                                   });
            if (it != range.second){
                auto ip_reply = it->pdu()->template rfind_pdu<Tins::IP>().src_addr();
                // Erase this response.

//                std::cout << "Responsive " << ip_reply << " " <<  std::chrono::microseconds(packet.timestamp()).count() << "\n";
                // Insert the reply in the responsiveness map
                auto ip_key = packets_per_interface.find(ip_reply.to_string());
                if (ip_key == packets_per_interface.end()) {
                    packets_per_interface.insert(std::make_pair(ip_reply.to_string(), std::vector<responsive_info_probe_t>()));
                }
                packets_per_interface[ip_reply.to_string()].push_back(std::make_pair(true, packet));

                icmp_replies.erase(it);
            } else {
                Tins::IPv4Address dst_ip;
                if (probing_style == probing_style_t::DIRECT){
                    // Match the ip probe with the destination in case of direct probing
                    dst_ip = ip->dst_addr();
                } else if (probing_style == probing_style_t::INDIRECT){
                    // Match the ip probe with the sport in case of indirect probing
                    for (const auto & matcher : matchers4){
                        if (match_probe(matcher.second, *ip)){
                            dst_ip = matcher.first;
                            break;
                        }
                    }

                }

                auto ip_key = packets_per_interface.find(dst_ip.to_string());
                if (ip_key == packets_per_interface.end()){
                    packets_per_interface.insert(std::make_pair(dst_ip.to_string(), std::vector<responsive_info_probe_t>()));
                }
                packets_per_interface[dst_ip.to_string()].push_back(std::make_pair(false, packet));

            }
        }
        else if (ip6 != nullptr){
            // Find the matching reply if existing.
            auto it = std::find_if(range.first, range.second,
                                   [&ip6](const Tins::Packet & matching_packet){


                                       auto pdu = matching_packet.pdu();
                                       auto reply_ip = pdu->find_pdu<IPv6>();
                                       auto icmp = pdu->find_pdu<ICMPv6>();

                                       // We assume direct probing so check only the source

                                       // Check first the destination
                                       auto destination = ip6->dst_addr();
                                       if (destination != reply_ip->src_addr()){
                                           return false;
                                       }

                                       if (icmp->type() == ICMPv6::Types::ECHO_REPLY){
                                           try{
                                               // We are in an ICMP direct probing so we match se probes with the icmp sequence number
                                               auto icmp_request = ip6->find_pdu<ICMPv6>();
                                               if (icmp_request != nullptr){
                                                   if (icmp->sequence() == icmp_request->sequence()
                                                       && icmp->identifier() == icmp_request->identifier()){
                                                       return true;
                                                   }
                                               }

                                           } catch (const Tins::malformed_packet & e){
                                               std::cerr << e.what() << "\n";
                                           }


                                       } else {
                                           // We are in a TCP or UDP probing so match with the probes with the ip id

                                       }
                                       return false;
                                   });
            if (it != range.second){
                auto ip_reply = it->pdu()->template rfind_pdu<Tins::IPv6>().src_addr();
                // Erase this response.

//                std::cout << "Responsive " << ip_reply << " " <<  std::chrono::microseconds(packet.timestamp()).count() << "\n";
                // Insert the reply in the responsiveness map
                auto ip_key = packets_per_interface.find(ip_reply.to_string());
                if (ip_key == packets_per_interface.end()) {
                    packets_per_interface.insert(std::make_pair(ip_reply.to_string(), std::vector<responsive_info_probe_t>()));
                }
                packets_per_interface[ip_reply.to_string()].push_back(std::make_pair(true, std::move(packet)));

                icmp_replies.erase(it);
            } else {
                IPv6Address dst_ip;
                if (probing_style == probing_style_t::DIRECT){
                    // Match the ip probe with the destination in case of direct probing
                    dst_ip = ip6->dst_addr();
                } else if (probing_style == probing_style_t::INDIRECT){

                }

                auto ip_key = packets_per_interface.find(dst_ip.to_string());
                if (ip_key == packets_per_interface.end()){
                    packets_per_interface.insert(std::make_pair(dst_ip.to_string(), std::vector<responsive_info_probe_t>()));
                }
                packets_per_interface[dst_ip.to_string()].push_back(std::make_pair(false, std::move(packet)));

            }
        }
    }





//    else if (is_v6){
//        for(const auto & packet : outgoing_packets) {
//            auto outgoing_pdu = packet.pdu();
//            // Find the IP layer
//            auto ip = outgoing_pdu->rfind_pdu<IPv6>();
//
//            auto it = std::find_if(icmp_replies.begin(), icmp_replies.end(), [&ip](const Tins::Packet & matching_packet){
//                auto pdu = matching_packet.pdu();
//                auto icmp = pdu->find_pdu<Tins::ICMPv6>();
//
//                auto reply_ip = pdu->find_pdu<IPv6>();
//
//                // We assume direct probing so check only the source
//
//                // Check first the destination
//                auto destination = ip.dst_addr();
//                if (destination != reply_ip->src_addr()){
//                    return false;
//                }
//
//                if (icmp->type() == Tins::ICMPv6::Types::ECHO_REPLY){
//                    try{
//                        // We are in an ICMP direct probing so we match se probes with the icmp id
//                        auto icmp_request = ip.find_pdu<ICMPv6>();
//                        if (icmp_request != nullptr){
//                            if (icmp->sequence() == icmp_request->sequence()){
//                                return true;
//                            }
//                        }
//
//                    } catch (const Tins::malformed_packet & e){
//                        std::cerr << e.what() << "\n";
//                    }
//
//
//                } else {
//                    // We are in a TCP or UDP probing so match with the probes with the ip id
//                    //TODO
//                }
//                return false;
//            });
//
//            if (it != icmp_replies.end()){
//                auto ip_reply = it->pdu()->template rfind_pdu<IPv6>().src_addr();
//                // Erase this response.
//
////                std::cout << "Responsive " << ip_reply << " " <<  std::chrono::microseconds(packet.timestamp()).count() << "\n";
//                // Insert the reply in the responsiveness map
//                auto ip_key = packets_per_interface6.find(ip_reply);
//                if (ip_key == packets_per_interface6.end()) {
//                    packets_per_interface6.insert(std::make_pair(ip_reply, std::vector<responsive_info_probe_t>()));
//                }
//                packets_per_interface6[ip_reply].push_back(std::make_pair(true, packet));
//
//                icmp_replies.erase(it);
//            } else {
//                Tins::IPv6Address dst_ip;
//                if (probing_style == probing_style_t::DIRECT){
//                    // Match the ip probe with the destination in case of direct probing
//                    dst_ip = ip.dst_addr();
//                }
//                else if (probing_style == probing_style_t::INDIRECT){
//                    //TODO v6 does not handle yet indirect
////                    // Match the ip probe with the sport in case of indirect probing
////                    for (const auto & matcher : matchers6){
////                        if (match_probe(matcher.second, ip)){
////                            dst_ip = matcher.first;
////                            break;
////                        }
////                    }
//
//                }
//
//                auto ip_key = packets_per_interface.find(dst_ip);
//                if (ip_key == packets_per_interface.end()){
//                    packets_per_interface6.insert(std::make_pair(dst_ip, std::vector<responsive_info_probe_t>()));
//                }
//                packets_per_interface6[dst_ip].push_back(std::make_pair(false, packet));
////                std::cout << "Unresponsive " << dst_ip << " " <<  std::chrono::microseconds(packet.timestamp()).count() << "\n";
//
//
//            }
//
//        }
//    }

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
                if (total_transition_state == 0){
                    loss_model.transition(i, j, 0);
                } else {
                    loss_model.transition(i, j, static_cast<double>(n_transitions[i][j])/ total_transition_state);
                }

            }
        }
    }


    return loss_model;
}


void rate_limit_analyzer_t::dump_transition_matrix(const gilbert_elliot_t &loss_model) {
    std::cout << "P(R, R) = " << loss_model.transition(0, 0) << "\n";
    std::cout << "P(R, U) = " << loss_model.transition(0, 1) << "\n";
    std::cout << "P(U, R) = " << loss_model.transition(1, 0) << "\n";
    std::cout << "P(U, U) = " << loss_model.transition(1, 1) << "\n";
}

rate_limit_analyzer_t::time_series_t rate_limit_analyzer_t::get_responsiveness(const std::string & address) {
    return extract_responsiveness_time_series(packets_per_interface[address]);
}


double rate_limit_analyzer_t::compute_loss_rate(const std::string & ip) const {
    return compute_loss_rate(packets_per_interface.at(ip));
}



std::vector<responsive_info_probe_t> rate_limit_analyzer_t::get_raw_packets(const std::string &ip) const {
    try {
        return packets_per_interface.at(ip);
    } catch (const std::out_of_range & e){
        std::cerr << "Keys found:\n";
        for (const auto & pair : packets_per_interface){
            std::cerr << pair.first << "\n";
        }
        std::cerr << "Was looking for key " << ip << "\n";
        std::cerr << "Error: May be network dynamics.\n";
    }
    return std::vector<responsive_info_probe_t>();
}

gilbert_elliot_t rate_limit_analyzer_t::compute_loss_model(const std::string &address) const{
    return compute_loss_model(packets_per_interface.at(address));
}

int rate_limit_analyzer_t::compute_change_point(const std::vector<int> &data, change_point_type_t cpt_type) const {
    // Create the R context
    if (!already_loaded){
        R_context.parseEvalQ(load_R_libraries);
        already_loaded = true;
    }
    R_context["data"] = data;

    std::string cpt_type_str;
    if (cpt_type == change_point_type_t::MEAN){
        cpt_type_str = "var";
    } else if (cpt_type == change_point_type_t::VAR){
        cpt_type_str = "var";
    }

    std::stringstream r_command;
    r_command << "data.man=cpt.";
    r_command << cpt_type_str;
    r_command << "(data, method='AMOC',penalty='Asymptotic', pen.value=0.05)";

    auto run_change_point_algorithm = r_command.str();
    //Manual penalty, less good. pen.value='50 * log(n)')");

    R_context.parseEvalQ(run_change_point_algorithm);

    Rcpp::NumericVector change_point_R = R_context.parseEval("cpts(data.man)");

    int change_point = change_point_R[0];

    if (change_point == 0){
        return static_cast<int>(data.size());
    }

    return change_point;
}

int rate_limit_analyzer_t::compute_change_point(
        const std::vector<responsive_info_probe_t> &data, change_point_type_t cp_type) const {

    // Early return if data is empty
    if (data.empty()){
        return static_cast<int>(data.size());
    }


    // Change to binary responses
    auto binary_responses = responsiveness_to_binary(data);


    auto change_point = compute_change_point(binary_responses, cp_type);

    return change_point;

}

std::unordered_map<std::string, int>
rate_limit_analyzer_t::compute_icmp_change_point() const {
    std::unordered_map<std::string, int> icmp_change_point;
    for (const auto & responsiveness_ip : packets_per_interface){
        auto change_point = compute_change_point(responsiveness_ip.second, change_point_type_t::MEAN);
        icmp_change_point[responsiveness_ip.first] = change_point;
    }
    return icmp_change_point;
}

int
rate_limit_analyzer_t::compute_change_point(const std::string &ip_address) const {
    auto raw = packets_per_interface.at(ip_address);
    auto change_point = compute_change_point(raw, change_point_type_t::MEAN);
    return change_point;
}


std::string rate_limit_analyzer_t::serialize_raw() {
    int i = 0;
    std::stringstream serialized_raw;
    serialized_raw << "{";
    for (const auto & address_packets : packets_per_interface){
        if (i != 0){
            serialized_raw << ",";
        }
        serialized_raw << "\"";
        serialized_raw << address_packets.first;
        serialized_raw << "\":";
        serialized_raw << serialize_raw(address_packets.first);

        i += 1;
    }
    serialized_raw << "}";

    return serialized_raw.str();
}

std::string rate_limit_analyzer_t::serialize_raw(const std::string & address) {

    int i = 0;

    std::stringstream serialized_raw;
    serialized_raw << "[";

    for (const auto & packet : packets_per_interface.at(address)){
        if (i != 0){
         serialized_raw << ", ";
        }
        if (packet.first){
            serialized_raw << "1";
        } else {
            serialized_raw << "0";
        }
        i += 1;
    }

    serialized_raw  << "]";

    return serialized_raw.str();
}



double rate_limit_analyzer_t::correlation(const std::vector<responsive_info_probe_t> &raw_router_1,
                   const std::vector<responsive_info_probe_t> &raw_router_2) {



    auto responsive_to_binary = [](const responsive_info_probe_t & responsive_info_probe){
        return responsive_info_probe.first ? 1 : 0;
    };

    std::vector<double> X;
    std::transform(raw_router_1.begin(), raw_router_1.end(), std::back_inserter(X), responsive_to_binary);
    std::vector<double> Y;
    std::transform(raw_router_2.begin(), raw_router_2.end(), std::back_inserter(Y), responsive_to_binary);

    auto cor = utils::cov_correlation(X, Y).second;

    return cor;
}


double rate_limit_analyzer_t::correlation(const std::string &ip_address1,
                                           const std::string &ip_address2) {
    return correlation(packets_per_interface[ip_address1], packets_per_interface[ip_address2]);
}

std::pair<std::vector<int>, std::vector<int>>
rate_limit_analyzer_t::adjust_time_series_length(const std::string &high_rate_ip_address, const std::string &low_rate_ip_address) {
    auto & packets_high_rate_interface = packets_per_interface[high_rate_ip_address];
    auto & packets_low_rate_interface  = packets_per_interface[low_rate_ip_address];

    auto n_bits = static_cast<int>(std::round(static_cast<double>(packets_high_rate_interface.size()) / packets_low_rate_interface.size()));


    std::vector<int> int_bits_high;
    std::vector<int> int_bits_low;

    // Transform low rate time series to replace 1's by n_bits
    std::transform(packets_low_rate_interface.begin(), packets_low_rate_interface.end(), std::back_inserter(int_bits_low),
                   [n_bits](const auto & responsiveness_packet){
                       if (responsiveness_packet.first){
                           return n_bits;
                       }
                       return 0;
                   });

    std::transform(packets_high_rate_interface.begin(), packets_high_rate_interface.end(), std::back_inserter(int_bits_high),
                   [](const auto & responsiveness_packet){
                       if (responsiveness_packet.first){
                           return 1;
                       }
                       return 0;
                   });

    std::vector<int> subsequences_high_rate;

    for (std::size_t i = 0; i + n_bits < int_bits_high.size(); i += n_bits){
        // Build subsequences of n_bits
        auto sum_bits = std::accumulate(int_bits_high.begin() + i, int_bits_high.begin() + i + n_bits, 0);
        subsequences_high_rate.push_back(sum_bits);
    }

    auto min_size = std::min(subsequences_high_rate.size(), int_bits_low.size());

    subsequences_high_rate.resize(min_size);
    int_bits_low.resize(min_size);


    return std::make_pair(subsequences_high_rate, int_bits_low);
}

double rate_limit_analyzer_t::correlation_high_low(const std::string &high_rate_ip_address,
                                                    const std::string &low_rate_ip_address) {


    /**
     * Adjust the number of bits, then compute the correlation.
     */

    // Adjust number of bits

    const auto equal_length_time_series = adjust_time_series_length(high_rate_ip_address, low_rate_ip_address);
    const auto & subsequences_high_rate = equal_length_time_series.first;
    const auto & int_bits_low = equal_length_time_series.second;
    // Compute correlation
    auto correlation = cov_correlation(subsequences_high_rate, int_bits_low).second;


    return correlation;
}

std::vector<int>
rate_limit_analyzer_t::responsiveness_to_binary(const std::vector<utils::responsive_info_probe_t> &responses) const{

    std::vector<int> binary_responses;

    std::transform(responses.begin(), responses.end(), std::back_inserter(binary_responses),
                   [](const auto & responsiveness_packet){
                       if (responsiveness_packet.first){
                           return 1;
                       }
                       return 0;
                   });
    return binary_responses;
}



rate_limit_analyzer_t::rate_limit_analyzer_t(const rate_limit_analyzer_t &other) :
        ip_family (other.ip_family),
        probing_style (other.probing_style),
        matchers4 (other.matchers4),
        matchers6 (other.matchers6),
        packets_per_interface(other.packets_per_interface),
        outgoing_packets(other.outgoing_packets),
        icmp_replies(other.icmp_replies)
{

}

rate_limit_analyzer_t rate_limit_analyzer_t::build_rate_limit_analyzer_t_from_probe_infos(const std::vector<probe_infos_t> &probes_infos) {
    std::unordered_map<IPv4Address, IP> matchers4;
    std::unordered_map<IPv6Address, IPv6> matchers6;

    rate_limit_analyzer_t rate_limit_analyzer;
    for (const auto & probe_infos : probes_infos){
        if (probe_infos.get_family() == PDU::PDUType::IP){
            matchers4.insert(std::make_pair(probe_infos.get_real_target4(), probe_infos.get_packet4()));
        } else if (probe_infos.get_family() == PDU::PDUType::IPv6){
            matchers6.insert(std::make_pair(probe_infos.get_real_target6(), probe_infos.get_packet6()));
        }


    }

    rate_limit_analyzer = rate_limit_analyzer_t(probes_infos[0].get_probing_style(), matchers4, matchers6);
    return rate_limit_analyzer;
}
















