//
// Created by System Administrator on 06/11/2018.
//

#include <string>
#include <sstream>
#include <fstream>      // std::ifstream
#include <probe_infos_t.hpp>
#include "../../include/utils/file_utils_t.hpp"

#include <tins/tins.h>

using namespace Tins;

namespace utils{


    // The format of the input file should be the following:
    // GROUP_ID, ADDRESS_FAMILY, PROBING_TYPE (DIRECT, INDIRECT), PROTOCOL (tcp, udp, icmp), INTERFACE_TYPE (CANDIDATE, WITNESS),
    // REAL_ADDRESS, PROBING_ADDRESS, FLOW_ID (v6), SRC_PORT(v4) , DST_PORT(v4).
    int group_id_index = 0;
    int address_family_index = 1;
    int probing_style_index = 2;
    int protocol_index = 3;
    int interface_type_index = 4;
    int real_address_index = 5;
    int probing_address_index = 6;
    int flow_ttl_index = 7;
    int flow_sport_index = 8;
    int flow_dport_index = 9;


    uint16_t default_sport = 24000;
    uint16_t default_dport = 33435;


    std::string build_pcap_name(const std::string & folder,
                                const std::string & icmp_type,
                                const std::string & destination,
                                const std::string & icmp_algo_type,
                                int rate){
        std::stringstream pcap_file_stream;
        pcap_file_stream << folder << icmp_type << "_" << destination << "_" << rate << "_" << icmp_algo_type << ".pcap";
        return pcap_file_stream.str();
    }

    std::vector<icmp_trigger_probes_t> build_icmp_trigger_probes_from_file(const std::string &file_name,
                                                                           const Tins::IPv4Address &source){
        std::vector<icmp_trigger_probes_t> alias_test;

        std::ifstream infile(file_name);
        // Each line correspond to a ttl_exceeded probe, so parse and build it
        std::string line;
        while (std::getline(infile, line))
        {
            std::vector<std::string> tokens;
            split(line, tokens, ' ');
            auto target_ip = tokens[0];
            auto probe_ip = tokens[1];
            auto ttl = static_cast<uint8_t>(std::atoi(tokens[2].c_str()));
            auto flow_id = static_cast<uint16_t>(std::atoi(tokens[3].c_str())) + 24000;



            // Build the different probes
            auto ttl_exceeded_probe = build_icmp_triggering_probe(probe_ip, source, flow_id, 33435, ttl, Tins::ICMP::TIME_EXCEEDED);
            auto dst_unreachable_probe = build_icmp_triggering_probe(target_ip, source,  24000, 33435, 0, Tins::ICMP::DEST_UNREACHABLE);
            auto echo_reply_probe = build_icmp_triggering_probe(target_ip, source, 0, 0, 0, Tins::ICMP::Flags::ECHO_REPLY);

            alias_test.push_back(icmp_trigger_probes_t{ttl_exceeded_probe, dst_unreachable_probe, echo_reply_probe});
        }
        return alias_test;
    }


    std::vector<std::string> extract_ips_from_filenames(const boost::filesystem::path & pcap_directory) {
//        std::regex ipv4_regex {"([0–9]{1,3}\\.){3}\\.([0–9]{1,3})"};
        std::regex ipv4_regex ("([0-9]{1,3}\\.){3}([0-9]{1,3})");

        std::vector<std::string> ips;
        for (boost::filesystem::directory_iterator itr(pcap_directory); itr != boost::filesystem::directory_iterator(); ++itr) {
            // Parse the file_name to retrieve probing type.
            std::string file_name{itr->path().filename().string()};
            std::smatch ip_match;
            if (std::regex_search(file_name, ip_match, ipv4_regex)) {
                auto it = std::find(ips.begin(), ips.end(), ip_match[0]);
                if (it == ips.end()){
                    ips.emplace_back(ip_match[0]);
                }

            }
        }
        return ips;
    }

    std::vector<probe_infos_t> parse_input_file(const char * input_file_path){
        std::vector<probe_infos_t> probes_infos;

        std::ifstream input_file(input_file_path);

        std::string line;
        while (std::getline(input_file, line))
        {
            if (line == std::string("")){
                continue;
            }
            line.erase(std::remove_if(line.begin(), line.end(), isspace), line.end());

            std::istringstream to_split(line);
            std::vector<std::string> tokens;
            std::string token;
            while (std::getline(to_split, token, ',')){
                tokens.emplace_back(token);
            }

            auto group_id = atoi(tokens[group_id_index].c_str());

            // Set the address family
            auto address_family = tokens[address_family_index];

            // Set the probing_style
            probing_style_t probing_style (probing_style_t::UNKNOWN);
            if (tokens[probing_style_index] == std::string("INDIRECT")){
                probing_style = probing_style_t::INDIRECT;
            } else if (tokens[probing_style_index] == std::string("DIRECT")){
                probing_style = probing_style_t::DIRECT;
            }
            if (probing_style == probing_style_t::UNKNOWN){
                std::cerr << "Bad PROBING_STYLE. Possible values are (DIRECT, INDIRECT)\n";
                throw std::exception();
            }

            PDU::PDUType protocol (PDU::PDUType::UNKNOWN);
            if (tokens[protocol_index] == std::string("tcp")){
                protocol = PDU::PDUType::TCP;
            } else if (tokens[protocol_index] == std::string("udp")){
                protocol = PDU::PDUType::UDP;
            } else if (tokens[protocol_index] == std::string("icmp")){
                protocol = PDU::PDUType::ICMP;
            }
            if (protocol == PDU::PDUType::UNKNOWN){
                std::cerr << "Bad PROTOCOL. Possible values are (tcp, udp, icmp)\n";
                throw std::exception();
            }


            // Set the interface_type
            interface_type_t interface_type (interface_type_t ::UNKNOWN);

            if (tokens[interface_type_index] == std::string("CANDIDATE")){
                interface_type = interface_type_t::CANDIDATE;
            } else if (tokens[interface_type_index] == std::string("WITNESS")){
                interface_type = interface_type_t::WITNESS;
            }
            if (interface_type == interface_type_t::UNKNOWN){
                std::cerr << "Bad INTERFACE_TYPE. Possible values are (CANDIDATE, WITNESS)\n";
                throw std::exception();
            }



            IP probe;
            IPv6 probe6;
            if (address_family == std::string("4")){
                // Set the real address
                IPv4Address real_address {tokens[real_address_index]};
                // Do not add if address already in the vector.
                auto is_already_in_addresses_it = std::find_if(probes_infos.begin(), probes_infos.end(), [&real_address](const auto & probe_infos){
                   return probe_infos.get_real_target() == real_address.to_string();
                });

                if (is_already_in_addresses_it != probes_infos.end()){
                    continue;
                }

                // Set the probing address
                IPv4Address probing_address {tokens[probing_address_index]};
                probe.dst_addr(probing_address);
                probe.src_addr(NetworkInterface::default_interface().ipv4_address());
                if (probing_style == probing_style_t::DIRECT) {
                    if (protocol == PDU::PDUType::ICMP) {
                        probe /= ICMP();
                    } else if (protocol == PDU::PDUType::UDP) {
                        probe /= UDP(default_dport, default_sport);

                    } else if (protocol == PDU::PDUType::TCP) {
                        probe /= TCP(default_dport, default_sport);
                    }
                    probe.ttl(64);
                } else if (probing_style == probing_style_t::INDIRECT) {
                    // Only UDP and TCP are supported
                    // Parse the flow used
                    uint8_t flow_ttl = atoi(tokens[flow_ttl_index].c_str());
                    uint16_t sport = atoi(tokens[flow_sport_index].c_str());
                    uint16_t dport = atoi(tokens[flow_dport_index].c_str());
                    if (protocol == PDU::PDUType::ICMP) {
                        std::cerr << "ICMP indirect probing is not supported\n";
                        throw std::exception();
                    } else if (protocol == PDU::PDUType::UDP) {
                        probe /= UDP(dport, sport);

                    } else if (protocol == PDU::PDUType::TCP) {
                        probe /= TCP(dport, sport);
                    }
                    probe.ttl(flow_ttl);
                }
                probe /= RawPDU("kevin.vermeulen@sorbonne-universite.fr");

                probes_infos.emplace_back(group_id, 1, probe, real_address, protocol,  probing_style, interface_type);

            } else if (address_family == std::string("6")){
                // Set the real address
                IPv6Address real_address {tokens[real_address_index]};
                auto is_already_in_addresses_it = std::find_if(probes_infos.begin(), probes_infos.end(), [&real_address](const auto & probe_infos){
                    return probe_infos.get_real_target() == real_address.to_string();
                });

                if (is_already_in_addresses_it != probes_infos.end()){
                    continue;
                }
                // Set the probing address
                IPv6Address probing_address {tokens[probing_address_index]};
                //TODO
                probe6.dst_addr(probing_address);
                probe6.src_addr(NetworkInterface::default_interface().ipv6_addresses()[0].address);
                if (probing_style == probing_style_t::DIRECT) {
                    if (protocol == PDU::PDUType::ICMP) {
                        probe6 /= ICMPv6();
                    } else if (protocol == PDU::PDUType::UDP) {
                        probe6 /= UDP(default_dport, default_sport);

                    } else if (protocol == PDU::PDUType::TCP) {
                        probe6 /= TCP(default_dport, default_sport);
                    }
                    probe6.hop_limit(64);
                }
                // Same rate by default
                probes_infos.emplace_back(group_id, 1, probe6, real_address, protocol,  probing_style, interface_type);
            }
            // Probing rate is by default the same for all the interfaces

        }
        return probes_infos;
    }


    std::stringstream build_output_line(const std::string & address,
                                        const std::string & type,
                                        int probing_rate,
                                        int change_behaviour_rate,
                                        double loss_rate,
                                        double transition_matrix_0_0,
                                        double transition_matrix_0_1,
                                        double transition_matrix_1_0,
                                        double transition_matrix_1_1,
                                        const std::unordered_map<std::string, double> & correlations){

        std::stringstream ostream;
        ostream << address << ", " << type << ", " << probing_rate << ", " <<  change_behaviour_rate << ", " << loss_rate <<", ";
        ostream << transition_matrix_0_0 << ", "  << transition_matrix_0_1  << ", " << transition_matrix_1_0 << ", " << transition_matrix_1_1;
        if (type == std::string("GROUPSPR") || type == std::string("GROUPDPR")){
            for (const auto & correlation_address : correlations){
                ostream << ", " << correlation_address.first << ": " << correlation_address.second;
            }
        }

        ostream << "\n";


        return ostream;
    }

    std::pair<double, double> parse_loss_rate_interval(const std::string & loss_rate_interval_str){
        std::pair<double, double> loss_rate_interval;

        std::regex loss_rate_interval_regex{"0[.][0-9]{1,2}"};


        std::smatch sm;
        int i = 0;
        std::string copy_loss_rate_interval_str = loss_rate_interval_str;
        while(std::regex_search(copy_loss_rate_interval_str, sm, loss_rate_interval_regex))
        {
            if (i == 0){
                loss_rate_interval.first = std::stod(sm.str());
            } else if (i == 1){
                loss_rate_interval.second = std::stod(sm.str());
            } else {
                std::cerr << "Invalid loss rate interval, exiting...\n";
                exit(1);
            }
            i += 1;
            copy_loss_rate_interval_str = sm.suffix();
        }

        return loss_rate_interval;

    }

}
