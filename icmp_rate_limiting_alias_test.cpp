//
// Created by System Administrator on 29/08/2018.
//
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <unordered_map>

#include <cmath>

#include <tins/tins.h>

#include <probe_infos_t.hpp>
#include <rate_limit_test_t.hpp>
#include <rate_limit_plotter_t.hpp>
#include <icmp_trigger_probes_t.hpp>
#include <utils/file_utils_t.hpp>

using namespace Tins;
using namespace utils;
namespace {

    std::vector<int> custom_rates {1000, 2000, 3000};

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
                probes_infos.emplace_back(group_id, 1, probe, real_address, protocol,  probing_style, interface_type);

            } else if (address_family == std::string("6")){
                // Set the real address
                IPv6Address real_address {tokens[real_address_index]};

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

    struct pairhash {
    public:
        template <typename T, typename U>
        std::size_t operator()(const std::pair<T, U> &x) const
        {
            return std::hash<T>()(x.first) ^ std::hash<U>()(x.second);
        }
    };

    template <typename Address>
    std::stringstream build_output_line(const Address & address,
                                        const std::string & type,
                                        int probing_rate, double loss_rate,
                                        const std::unordered_map<Address, double> correlations){

        std::stringstream ostream;
        ostream << address << ", " << type << ", " << probing_rate << ", " << loss_rate;

        if (type == std::string("GROUPSPR")){
            for (const auto & correlation_address : correlations){
                ostream << ", " << correlation_address.first << ": " << correlation_address.second;
            }
        }

        ostream << "\n";


        return ostream;
    }



    std::unordered_map<IPv4Address, std::unordered_map<int, packet_interval_t>> execute_individual_probes4(
            int max_probing_rate,
            const std::string &output_dir_individual,
            const std::vector<probe_infos_t> &probes_infos,
            std::stringstream & ostream){
        auto sniff_interface = NetworkInterface::default_interface();

        /**
        * Initialize data structures.
        */

        // Individual

        std::unordered_map<IPv4Address, std::unordered_map<int, std::string>> pcap_individual_file;
        std::unordered_map<IPv4Address, std::unordered_map<int, packet_interval_t>> triggering_rates;

        /**
     *  Probe each interface separately with progressive rates.
     */
        std::cout << "Proceeding to the individual probing phase...\n";

        // Progressively increase the sending rate (log scale)
        for (const auto & probe_infos : probes_infos){
            pcap_individual_file.insert(std::make_pair(probe_infos.get_real_target4(), std::unordered_map<int, std::string>()));
            triggering_rates.insert(std::make_pair(probe_infos.get_real_target4(), std::unordered_map<int, packet_interval_t>()));
            bool has_found_triggering_rate = false;
//            for(int i = 10; std::pow(2, i) < max_probing_rate; ++i){
            for(const auto & probing_rate : custom_rates){
                // Probing rate represents the number of packets to send in 1 sec
//                auto probing_rate = static_cast<int>(pow(2, i));
                auto nb_probes = 5 * probing_rate;

                rate_limit_test_t<IPv4Address> rate_limit_test(nb_probes, probing_rate, sniff_interface,
                                                  std::vector<probe_infos_t>(1, probe_infos));

                auto icmp_type = probe_infos.icmp_type_str();

                auto real_target = probe_infos.get_real_target4();
                auto pcap_file_name = build_pcap_name(output_dir_individual, icmp_type, real_target.to_string(), probing_rate);
                pcap_individual_file[real_target][probing_rate] =  pcap_file_name;
                rate_limit_test.set_pcap_file(pcap_file_name);

                std::cout << "Starting " << icmp_type <<  " for " << real_target.to_string() << " with probing rate " << probing_rate <<  "...\n";
                rate_limit_test.start();

                /**
                *  Determine the rate where the responding behaviour changes for each interface (Technique: compute loss rates on intervals)
                */
                std::unordered_map<IPv4Address, IP> matchers;
                matchers.insert(std::make_pair(probe_infos.get_real_target4(), probe_infos.get_packet4()));
                rate_limit_analyzer_t rate_limit_analyzer(probe_infos.get_probing_style(), matchers) ;

                // Start the analysis of responsiveness.
                rate_limit_analyzer.start(pcap_individual_file.at(probe_infos.get_real_target4()).at(probing_rate));

                // Extract loss rate.
                auto loss_rate = rate_limit_analyzer.compute_loss_rate(probe_infos.get_real_target4());
                std::cout << "Loss rate: " << loss_rate << "\n";
                // Now extract relevant infos.
                auto triggering_rates_per_ip = rate_limit_analyzer.compute_icmp_triggering_rate4();
                if (triggering_rates_per_ip.at(real_target) != std::make_pair(-1, -1)) {
                    triggering_rates[real_target][probing_rate] = triggering_rates_per_ip[real_target];

                    auto line_ostream = build_output_line(probe_infos.get_real_target4(), "INDIVIDUAL", probing_rate, loss_rate,
                                                          std::unordered_map<IPv4Address, double>());
                    ostream << line_ostream.str();
                    if (has_found_triggering_rate) {
                        break;
                    }
                    has_found_triggering_rate = true;
                }

                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }


        for (const auto & triggering_rate : triggering_rates) {
            for (const auto & rate_triggering_rate : triggering_rate.second){
                std::cout << "Rate: " << rate_triggering_rate.first << "\n";
                std::cout << triggering_rate.first << ": (" << rate_triggering_rate.second.first << ", " << rate_triggering_rate.second.second << ")\n";
            }
        }
        return triggering_rates;
    }


    std::unordered_map<IPv6Address, std::unordered_map<int, packet_interval_t>> execute_individual_probes6(
            int max_probing_rate,
            const std::string &output_dir_individual,
            const std::vector<probe_infos_t> &probes_infos, std::stringstream & ostream){
        auto sniff_interface = NetworkInterface::default_interface();

        /**
        * Initialize data structures.
        */

        // Individual

        std::unordered_map<IPv6Address, std::unordered_map<int, std::string>> pcap_individual_file;
        std::unordered_map<IPv6Address, std::unordered_map<int, packet_interval_t>> triggering_rates;

        /**
     *  Probe each interface separately with progressive rates.
     */
        std::cout << "Proceeding to the individual probing phase...\n";


        for (const auto & probe_infos : probes_infos){


            pcap_individual_file.insert(std::make_pair(probe_infos.get_real_target6(), std::unordered_map<int, std::string>()));
            triggering_rates.insert(std::make_pair(probe_infos.get_real_target6(), std::unordered_map<int, packet_interval_t>()));
            bool has_found_triggering_rate = false;
            // Progressively increase the sending rate (log scale)
//            for(int i = 10; std::pow(2, i) < max_probing_rate; ++i){
            for(const auto & probing_rate : custom_rates){

                // Probing rate represents the number of packets to send in 1 sec
                auto nb_probes = 5 * probing_rate;

                rate_limit_test_t<IPv6Address> rate_limit_test(nb_probes, probing_rate, sniff_interface,
                                                               std::vector<probe_infos_t>(1, probe_infos));

                auto icmp_type = probe_infos.icmp_type_str();

                auto real_target = probe_infos.get_real_target6();
                auto pcap_file_name = build_pcap_name(output_dir_individual, icmp_type, real_target.to_string(), probing_rate);
                pcap_individual_file[real_target][probing_rate] =  pcap_file_name;
                rate_limit_test.set_pcap_file(pcap_file_name);

                std::cout << "Starting " << icmp_type <<  " for " << real_target.to_string() << " with probing rate " << probing_rate <<  "...\n";
                rate_limit_test.start();

                /**
                *  Determine the rate where the responding behaviour changes for each interface (Technique: compute loss rates on intervals)
                */
                std::unordered_map<IPv6Address, IPv6> matchers;
                matchers.insert(std::make_pair(probe_infos.get_real_target6(), probe_infos.get_packet6()));
                rate_limit_analyzer_t rate_limit_analyzer(probe_infos.get_probing_style(), matchers) ;

                // Start the analysis of responsiveness.
                rate_limit_analyzer.start(pcap_individual_file.at(probe_infos.get_real_target6()).at(probing_rate));

                // Extract loss rate.
                auto loss_rate = rate_limit_analyzer.compute_loss_rate(probe_infos.get_real_target6());
                std::cout << "Loss rate: " << loss_rate << "\n";
                // Now extract relevant infos.
                auto triggering_rates_per_ip = rate_limit_analyzer.compute_icmp_triggering_rate6();
                if (triggering_rates_per_ip.at(real_target) != std::make_pair(-1, -1)) {
                    triggering_rates[real_target][probing_rate] = triggering_rates_per_ip[real_target];

                    auto line_ostream = build_output_line(probe_infos.get_real_target6(), "INDIVIDUAL", probing_rate, loss_rate,
                                                          std::unordered_map<IPv6Address, double>());

                    ostream << line_ostream.str();
                    if (has_found_triggering_rate) {
                        break;
                    }
                    has_found_triggering_rate = true;
                }

                std::this_thread::sleep_for(std::chrono::seconds(5));
            }

        }


        for (const auto & triggering_rate : triggering_rates) {
            for (const auto & rate_triggering_rate : triggering_rate.second){
                std::cout << "Rate: " << rate_triggering_rate.first << "\n";
                std::cout << triggering_rate.first << ": (" << rate_triggering_rate.second.first << ", " << rate_triggering_rate.second.second << ")\n";
            }
        }
        return triggering_rates;
    }


    void execute_group_probes4(int max_probing_rate, const std::string & output_dir_groups,
                               const std::unordered_map<IPv4Address, std::unordered_map<int, packet_interval_t>> & triggering_rates,
                               const std::vector<probe_infos_t> & probes_infos,
                               const std::string & group_type,
                               std::stringstream & ostream) {

        auto sniff_interface = NetworkInterface::default_interface();

        /**
         * - Build groups
         * - Probe groups of interfaces with rates that can trigger RL.
         * - Determine the rate where the responding behaviour changes.
         */

        /**
         * Initialize data structures
         */

        std::unordered_map<int, std::unordered_map<int, std::string>> pcap_groups_files;
        std::unordered_map<IPv4Address, std::unordered_map<int, packet_interval_t >> triggering_rates_groups;

        // Build groups
        std::cout << "Building groups\n";

        std::unordered_map<int, std::vector<probe_infos_t> > groups;
        std::for_each(probes_infos.begin(), probes_infos.end(), [&groups](const probe_infos_t &probe_info) {
            auto group_id = probe_info.get_group_id();
            auto has_key = groups.find(group_id);
            if (has_key == groups.end()) {
                groups[group_id] = std::vector<probe_infos_t>();
            }
            groups[group_id].push_back(probe_info);
        });


        // Probe groups
        for (const auto &group : groups) {
            std::unordered_map<IPv4Address, std::unordered_map<int, double>> loss_rates;
            std::unordered_map<IPv4Address, std::unordered_map<int, std::vector<responsive_info_probe_t>>> raw_responsiveness_candidates;
            std::unordered_map<IPv4Address, std::unordered_map<int, std::vector<responsive_info_probe_t>>> raw_responsiveness_witnesses;

            //TODO Optimize the groups by changing those who have a non coherent (to determine) triggering rate.
            auto min_probing_rate_group = 0;
            auto max_probing_rate_group = 0;
            auto icmp_type = group.second[0].icmp_type_str();
            std::unordered_map<IPv4Address, IP> matchers;
            std::unordered_set<int> ratios_rates;
            probing_style_t probing_style = group.second[0].get_probing_style();
            for (const auto &probe_info : group.second) {
                // Find the min triggering rates from the data structures.
                auto real_target = probe_info.get_real_target4();
                auto intervals_target = triggering_rates.at(real_target);
                for (const auto &rates : intervals_target) {
                    if (rates.second != std::make_pair(-1, -1)) {
                        if (rates.first < min_probing_rate_group or min_probing_rate_group == 0) {
                            min_probing_rate_group = rates.first;
                        }
                        if (rates.first > max_probing_rate_group) {
                            max_probing_rate_group = rates.first;
                        }
                    }
                }

                // Check if they all have the same rate
                ratios_rates.insert(probe_info.get_probing_rate());

                // Prepare the analysis
                matchers.insert(std::make_pair(probe_info.get_real_target4(), probe_info.get_packet4()));


            }
            for (auto probing_rate : custom_rates) {
                if (probing_rate < min_probing_rate_group  or probing_rate > max_probing_rate_group){
                    continue;
                }

                // Multiply the probing rate to get the minimum probing rate to trigger.
                probing_rate *= group.second.size();
                if (probing_rate > max_probing_rate){
                    continue;
                }

                auto nb_probes = 5 * probing_rate;


                rate_limit_test_t<IPv4Address> rate_limit_test(nb_probes, probing_rate, sniff_interface, group.second);

                auto pcap_file_name = build_pcap_name(output_dir_groups, icmp_type, to_file_name(group.second, '_'),
                                                      probing_rate);
                pcap_groups_files[group.first][probing_rate] = pcap_file_name;
                rate_limit_test.set_pcap_file(pcap_file_name);

                std::cout << "Starting " << icmp_type << " for " << pcap_file_name << " with probing rate "
                          << probing_rate << "...\n";
                rate_limit_test.start();

                rate_limit_analyzer_t rate_limit_analyzer(probing_style, matchers);


                // Start the analysis of responsiveness.
                rate_limit_analyzer.start(pcap_groups_files.at(group.first).at(probing_rate));

                // Now extract relevant infos.
                for (const auto &probe_info : group.second) {
                    auto loss_rate = rate_limit_analyzer.compute_loss_rate(probe_info.get_real_target4());
                    std::cout << probe_info.get_real_target4() << " loss rate: " << loss_rate << "\n";
                    loss_rates[probe_info.get_real_target4()][probing_rate] = loss_rate;
                }

                // Triggering rate
                auto triggering_rates_per_ip = rate_limit_analyzer.compute_icmp_triggering_rate4();

                for (const auto &probe_info : group.second) {
                    auto real_target = probe_info.get_real_target4();
                    if (triggering_rates_per_ip.at(real_target) != std::make_pair(-1, -1)) {
                        triggering_rates_groups[real_target][probing_rate] = triggering_rates_per_ip[real_target];
                    }
                    // Raw data
                    auto raw = rate_limit_analyzer.get_raw_packets4(real_target);
                    if (probe_info.get_interface_type() == interface_type_t::CANDIDATE) {
                        raw_responsiveness_candidates[real_target][probing_rate] = raw;
                    } else if (probe_info.get_interface_type() == interface_type_t::WITNESS) {
                        raw_responsiveness_witnesses[real_target][probing_rate] = raw;
                    }

                }
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }

            if (group_type == "GROUPSPR") {
                rate_limit_plotter_t<IPv4Address> plotter;

                std::unordered_map<std::pair<IPv4Address, IPv4Address>, std::unordered_map<int, double>, pairhash> correlations;
                auto raw_responsiveness_candidates_witness = extend(raw_responsiveness_candidates, raw_responsiveness_witnesses);
                for (const auto & raw_responsiveness1 : raw_responsiveness_candidates_witness){
                    auto address1 = raw_responsiveness1.first;
                    auto rates_raw1 = raw_responsiveness1.second;
                    for (const auto & rate_raw1 : rates_raw1){
                        auto rate1 = rate_raw1.first;
                        auto raw1 = rate_raw1.second;
                        for (const auto & raw_responsiveness2 : raw_responsiveness_candidates_witness){
                            auto address2 = raw_responsiveness2.first;
                            auto rates_raw2 = raw_responsiveness2.second;
                            if (address1 == address2){
                                continue;
                            }
                            for (const auto & rate_raw2 : rates_raw2){
                                auto rate2 = rate_raw2.first;
                                auto raw2 = rate_raw2.second;
                                if (rate1 == rate2){
                                    auto has_key = correlations.find(std::make_pair(address1, address2));
                                    if (has_key != correlations.end()){
                                        if (has_key->second.find(rate1) != has_key->second.end())
                                            continue;
                                    }
                                    auto correlation = plotter.correlation(raw1, raw2);
                                    correlations[std::make_pair(address1, address2)][rate1] = correlation;
                                    correlations[std::make_pair(address2, address1)][rate1] = correlation;
                                }
                            }
                        }

                    }


                }
                for (const auto &probe_info : group.second) {
                    auto real_target4 = probe_info.get_real_target4();
                    for (auto probing_rate : custom_rates) {
                        if (probing_rate < min_probing_rate_group  or probing_rate > max_probing_rate_group){
                            continue;
                        }

                        // Multiply the probing rate to get the minimum probing rate to trigger.
                        probing_rate *= group.second.size();
                        if (probing_rate > max_probing_rate){
                            continue;
                        }

                        // Extract the relevant correlations
                        std::unordered_map<IPv4Address, double> correlations_map;

                        for (const auto & correlation : correlations){
                            auto address1 = correlation.first.first;
                            auto address2 = correlation.first.second;

                            auto correlation_rates_1_2 = correlation.second;
                            if (address1 == real_target4) {
                                for (const auto & correlation_rate_1_2 : correlation_rates_1_2){
                                    auto correlation_rate = correlation_rate_1_2.first;
                                    auto correlation_1_2 = correlation_rate_1_2.second;
                                    if (probing_rate == correlation_rate){
                                        correlations_map[address2] = correlation_1_2;
                                    }
                                }
                            }
                        }
                        auto line_stream = build_output_line(real_target4, "GROUPSPR",
                                                             probing_rate, loss_rates[real_target4][probing_rate],
                                                             correlations_map
                        );
                        ostream << line_stream.str();
                    }
                }
            } else {
                for (const auto &probe_info : group.second) {

                    auto real_target4 = probe_info.get_real_target4();
                    for (auto probing_rate : custom_rates) {
                        if (probing_rate < min_probing_rate_group  or probing_rate > max_probing_rate_group){
                            continue;
                        }

                        // Multiply the probing rate to get the minimum probing rate to trigger.
                        probing_rate *= group.second.size();
                        if (probing_rate > max_probing_rate){
                            continue;
                        }
                        auto line_stream = build_output_line(real_target4, "GROUPDPR",
                                                             probing_rate, loss_rates[real_target4][probing_rate],
                                                             std::unordered_map<IPv4Address, double>());
                        ostream << line_stream.str();
                    }
                }
            }

        }
    }

    void execute_group_probes6(int max_probing_rate, const std::string & output_dir_groups,
                              const std::unordered_map<IPv6Address, std::unordered_map<int, packet_interval_t>> & triggering_rates,
                              const std::vector<probe_infos_t> & probes_infos,
                              const std::string & group_type,
                              std::stringstream & ostream) {

        auto sniff_interface = NetworkInterface::default_interface();

        /**
         * - Build groups
         * - Probe groups of interfaces with rates that can trigger RL.
         * - Determine the rate where the responding behaviour changes.
         */

        /**
         * Initialize data structures
         */

        std::unordered_map<int, std::unordered_map<int, std::string>> pcap_groups_files;
        std::unordered_map<IPv6Address, std::unordered_map<int, packet_interval_t >> triggering_rates_groups;

        // Build groups
        std::cout << "Building groups\n";

        std::unordered_map<int, std::vector<probe_infos_t> > groups;
        std::for_each(probes_infos.begin(), probes_infos.end(), [&groups](const probe_infos_t &probe_info) {
            auto group_id = probe_info.get_group_id();
            auto has_key = groups.find(group_id);
            if (has_key == groups.end()) {
                groups[group_id] = std::vector<probe_infos_t>();
            }
            groups[group_id].push_back(probe_info);
        });


        // Probe groups
        for (const auto &group : groups) {
            std::unordered_map<IPv6Address, std::unordered_map<int, double>> loss_rates;
            std::unordered_map<IPv6Address, std::unordered_map<int, std::vector<responsive_info_probe_t>>> raw_responsiveness_candidates;
            std::unordered_map<IPv6Address, std::unordered_map<int, std::vector<responsive_info_probe_t>>> raw_responsiveness_witnesses;

            //TODO Optimize the groups by changing those who have a non coherent (to determine) triggering rate.
            auto min_probing_rate_group = 0;
            auto max_probing_rate_group = 0;
            auto icmp_type = group.second[0].icmp_type_str();
            std::unordered_map<IPv6Address, IPv6> matchers;
            std::unordered_set<int> ratios_rates;
            probing_style_t probing_style = group.second[0].get_probing_style();
            for (const auto &probe_info : group.second) {
                // Find the min triggering rates from the data structures.
                auto real_target = probe_info.get_real_target6();
                auto intervals_target = triggering_rates.at(real_target);
                for (const auto &rates : intervals_target) {
                    if (rates.second != std::make_pair(-1, -1)) {
                        if (rates.first < min_probing_rate_group or min_probing_rate_group == 0) {
                            min_probing_rate_group = rates.first;
                        }
                        if (rates.first > max_probing_rate_group) {
                            max_probing_rate_group = rates.first;
                        }
                    }
                }

                // Check if they all have the same rate
                ratios_rates.insert(probe_info.get_probing_rate());

                // Prepare the analysis
                matchers.insert(std::make_pair(probe_info.get_real_target6(), probe_info.get_packet6()));


            }
            for (auto probing_rate : custom_rates) {
                if (probing_rate < min_probing_rate_group  or probing_rate > max_probing_rate_group){
                    continue;
                }

                // Multiply the probing rate to get the minimum probing rate to trigger.
                probing_rate *= group.second.size();
                if (probing_rate > max_probing_rate){
                    continue;
                }

                auto nb_probes = 5 * probing_rate;


                rate_limit_test_t<IPv6Address> rate_limit_test(nb_probes, probing_rate, sniff_interface, group.second);

                auto pcap_file_name = build_pcap_name(output_dir_groups, icmp_type, to_file_name(group.second, '_'),
                                                      probing_rate);
                pcap_groups_files[group.first][probing_rate] = pcap_file_name;
                rate_limit_test.set_pcap_file(pcap_file_name);

                std::cout << "Starting " << icmp_type << " for " << pcap_file_name << " with probing rate "
                          << probing_rate << "...\n";
                rate_limit_test.start();

                rate_limit_analyzer_t rate_limit_analyzer(probing_style, matchers);


                // Start the analysis of responsiveness.
                rate_limit_analyzer.start(pcap_groups_files.at(group.first).at(probing_rate));

                // Now extract relevant infos.
                for (const auto &probe_info : group.second) {
                    auto loss_rate = rate_limit_analyzer.compute_loss_rate(probe_info.get_real_target6());
                    std::cout << probe_info.get_real_target6() << " loss rate: " << loss_rate << "\n";
                    loss_rates[probe_info.get_real_target6()][probing_rate] = loss_rate;
                }

                // Triggering rate
                auto triggering_rates_per_ip = rate_limit_analyzer.compute_icmp_triggering_rate6();

                for (const auto &probe_info : group.second) {
                    auto real_target = probe_info.get_real_target6();
                    if (triggering_rates_per_ip.at(real_target) != std::make_pair(-1, -1)) {
                        triggering_rates_groups[real_target][probing_rate] = triggering_rates_per_ip[real_target];
                    }
                    // Raw data
                    auto raw = rate_limit_analyzer.get_raw_packets6(real_target);
                    if (probe_info.get_interface_type() == interface_type_t::CANDIDATE) {
                        raw_responsiveness_candidates[real_target][probing_rate] = raw;
                    } else if (probe_info.get_interface_type() == interface_type_t::WITNESS) {
                        raw_responsiveness_witnesses[real_target][probing_rate] = raw;
                    }

                }
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }

            if (group_type == "GROUPSPR") {
                rate_limit_plotter_t<IPv6Address> plotter;

                std::unordered_map<std::pair<IPv6Address, IPv6Address>, std::unordered_map<int, double>, pairhash> correlations;
                auto raw_responsiveness_candidates_witness = extend(raw_responsiveness_candidates, raw_responsiveness_witnesses);
                for (const auto & raw_responsiveness1 : raw_responsiveness_candidates_witness){
                    auto address1 = raw_responsiveness1.first;
                    auto rates_raw1 = raw_responsiveness1.second;
                    for (const auto & rate_raw1 : rates_raw1){
                        auto rate1 = rate_raw1.first;
                        auto raw1 = rate_raw1.second;
                        for (const auto & raw_responsiveness2 : raw_responsiveness_candidates_witness){
                            auto address2 = raw_responsiveness2.first;
                            auto rates_raw2 = raw_responsiveness2.second;
                            if (address1 == address2){
                                continue;
                            }
                            for (const auto & rate_raw2 : rates_raw2){
                                auto rate2 = rate_raw2.first;
                                auto raw2 = rate_raw2.second;
                                if (rate1 == rate2){
                                    auto has_key = correlations.find(std::make_pair(address1, address2));
                                    if (has_key != correlations.end()){
                                        if (has_key->second.find(rate1) != has_key->second.end())
                                        continue;
                                    }
                                    auto correlation = plotter.correlation(raw1, raw2);
                                    correlations[std::make_pair(address1, address2)][rate1] = correlation;
                                    correlations[std::make_pair(address2, address1)][rate1] = correlation;
                                }
                            }
                        }

                    }


                }
                for (const auto &probe_info : group.second) {
                    auto real_target6 = probe_info.get_real_target6();
                    for (auto probing_rate : custom_rates) {
                        if (probing_rate < min_probing_rate_group  or probing_rate > max_probing_rate_group){
                            continue;
                        }

                        // Multiply the probing rate to get the minimum probing rate to trigger.
                        probing_rate *= group.second.size();
                        if (probing_rate > max_probing_rate){
                            continue;
                        }

                        // Extract the relevant correlations
                        std::unordered_map<IPv6Address, double> correlations_map;

                        for (const auto & correlation : correlations){
                            auto address1 = correlation.first.first;
                            auto address2 = correlation.first.second;

                            auto correlation_rates_1_2 = correlation.second;
                            if (address1 == real_target6) {
                                for (const auto & correlation_rate_1_2 : correlation_rates_1_2){
                                    auto correlation_rate = correlation_rate_1_2.first;
                                    auto correlation_1_2 = correlation_rate_1_2.second;
                                    if (probing_rate == correlation_rate){
                                        correlations_map[address2] = correlation_1_2;
                                    }
                                }
                            }
                        }
                        auto line_stream = build_output_line(real_target6, "GROUPSPR",
                                                             probing_rate, loss_rates[real_target6][probing_rate],
                                                             correlations_map
                                                             );
                        ostream << line_stream.str();
                    }
                }
            } else {
                for (const auto &probe_info : group.second) {

                    auto real_target6 = probe_info.get_real_target6();
                    for (auto probing_rate : custom_rates) {
                        if (probing_rate < min_probing_rate_group  or probing_rate > max_probing_rate_group){
                            continue;
                        }

                        // Multiply the probing rate to get the minimum probing rate to trigger.
                        probing_rate *= group.second.size();
                        if (probing_rate > max_probing_rate){
                            continue;
                        }
                        auto line_stream = build_output_line(real_target6, "GROUPDPR",
                                                             probing_rate, loss_rates[real_target6][probing_rate],
                                                             std::unordered_map<IPv6Address, double>());
                        ostream << line_stream.str();
                    }
                }
            }

        }
    }

}

int main(int argc, char * argv[]){
    /**
    * END TO END ALGORITHM TO DETERMINE IF TWO ADDRESSES ARE ALIASES.
    * - Probe each interface separately with progressive rates.
    * - Determine the rate where the responding behaviour changes for each interface (Technique: compute loss rates on intervals)
    * - Probe trios of interfaces with progressive rates, two are the candidates, one is the witness.
    * - Determine the rate where the responding behaviour changes.
    * - Compute correlation between candidates/witness
    * - Probe trios of interfaces with different rates
    * - Compute loss rate
    * - Conclude: if the changing rates are different from single candidate
    * to two candidates and the correlation is high between candidates, and low
    * between candidates and witness, conclude that they are aliases.
    *
    */

    // The format of the input file should be the following:
    // GROUP_ID, ADDRESS_FAMILY, PROBING_TYPE (DIRECT, INDIRECT), PROTOCOL (tcp, udp, icmp), INTERFACE_TYPE (CANDIDATE, WITNESS),
    // REAL_ADDRESS, PROBING_ADDRESS, FLOW_ID (v6), SRC_PORT(v4) , DST_PORT(v4).
    if (argc < 1){
        fprintf(stderr, "Usage: <input_file>");
    }

    /**
     * Parse input file
     */
    auto input_file_path = argv[1];

    auto probes_infos = parse_input_file(input_file_path);


    /**
     * Initialize default values
     */

    auto max_probing_rate = 10000;

    std::string output_dir_individual {"resources/pcap/individual/"};
    std::string output_dir_groups {"resources/pcap/groups/"};


    // Groups


    /**
     * Initialize aliases
     */
    std::vector<std::vector<probe_infos_t>> aliases;


    /**
     * Initialize output stream
     */

    std::stringstream ostream;

    if (probes_infos[0].get_family() == PDU::PDUType::IP){
        // Individual probing
        auto trigerring_rates = execute_individual_probes4(max_probing_rate, output_dir_individual, probes_infos, ostream);

        // Group probing same rate
        std::cout << "Proceeding to probing groups phase with same probing rate\n";
        execute_group_probes4(max_probing_rate, output_dir_groups, trigerring_rates, probes_infos, "GROUPSPR", ostream);

        // Group probing different rate
        auto ratio_rate = 8;
        // Change the rate of 1 candidate by ratio_rate
        std::vector<probe_infos_t> probes_infos_different_rates (probes_infos.begin(), probes_infos.end());
        for (auto & probe_infos: probes_infos_different_rates){
            if (probe_infos.get_interface_type() == interface_type_t::CANDIDATE){
                probe_infos.set_probing_rate(ratio_rate);
                break;
            }
        }

        std::cout << "Proceeding to probing groups phase with different probing rate\n";
        execute_group_probes4(max_probing_rate, output_dir_groups, trigerring_rates, probes_infos_different_rates, "GROUPDPR", ostream);

    } else if (probes_infos[0].get_family() == PDU::PDUType::IPv6){
        // Individual probing
        auto trigerring_rates = execute_individual_probes6(max_probing_rate, output_dir_individual, probes_infos, ostream);

        // Group probing same rate
        std::cout << "Proceeding to probing groups phase with same probing rate\n";
        execute_group_probes6(max_probing_rate, output_dir_groups, trigerring_rates, probes_infos, "GROUPSPR", ostream);

        // Group probing different rate
        auto ratio_rate = 8;
        // Change the rate of 1 candidate by ratio_rate
        std::vector<probe_infos_t> probes_infos_different_rates (probes_infos.begin(), probes_infos.end());
        for (auto & probe_infos: probes_infos_different_rates){
            if (probe_infos.get_interface_type() == interface_type_t::CANDIDATE){
                probe_infos.set_probing_rate(ratio_rate);
                break;
            }
        }

        std::cout << "Proceeding to probing groups phase with different probing rate\n";
        execute_group_probes6(max_probing_rate, output_dir_groups, trigerring_rates, probes_infos_different_rates, "GROUPDPR", ostream);
    }

    std::cout << ostream.str();
    // Take a decision if they are aliases, not aliases, or not possible to decide




}

