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

#include <boost/program_options.hpp>

#include <tins/tins.h>

#include <probe_infos_t.hpp>
#include <rate_limit_test_t.hpp>
#include <rate_limit_plotter_t.hpp>
#include <rate_limit_individual_t.hpp>
#include <rate_limit_group_t.hpp>
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

    namespace po = boost::program_options;

    std::string help_message = "";

    bool analyse_only = false;
    bool probe_only = false;
    auto targets_file_path = std::string("");
    std::string output_dir_individual {"resources/pcap/individual/"};
    std::string output_dir_groups {"resources/pcap/groups/"};

    // Declare the supported options.
    po::options_description desc("Allowed options");
    desc.add_options()
            ("help,h", help_message.c_str())
            ("targets-file,t", po::value<std::string>(), "Format is GROUP_ID, ADDRESS_FAMILY, PROBING_TYPE (DIRECT, INDIRECT), PROTOCOL (tcp, udp, icmp), INTERFACE_TYPE (CANDIDATE, WITNESS),"\
                                                     "REAL_ADDRESS, PROBING_ADDRESS, FLOW_ID (v6), SRC_PORT(v4) , DST_PORT(v4)." )
            ("individual-dir,i", po::value<std::string>(), "directory for individual probing pcap files")
            ("group-dir,g", po::value<std::string>(), "directory for group probing pcap files")
            ("analyse-only,a", "do not probe, only start analysis")
            ("probe-only,p", "do not analyse, only probe");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << "\n";
        return 1;
    }

    if (vm.count("targets-file")) {
        targets_file_path = vm["targets-file"].as<std::string>();
        std::cout << "Targets file was set to "
             << targets_file_path << ".\n";


    } else {
        std::cerr << "Missing targets file. Exiting...\n";
        exit(1);
    }

    if (vm.count("individual-dir")) {
        output_dir_individual = vm["individual-dir"].as<std::string>();
        std::cout << "output individual dir set to  "
                  << output_dir_individual << ".\n";


    }

    if (vm.count("group-dir")) {
        output_dir_groups = vm["group-dir"].as<std::string>();
        std::cout << "output groups dir set to  "
                  << output_dir_groups << ".\n";
    }

    if (vm.count("analyse-only")) {
        analyse_only = true;
    }
    if (vm.count("probe-only")) {
        probe_only = true;
    }


    auto probes_infos = parse_input_file(targets_file_path.c_str());


    /**
     * Initialize default values
     */

    auto max_probing_rate = 10000;


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
        rate_limit_individual_t rate_limit_individual;
        rate_limit_group_t rate_limit_group;
        rate_limit_group_t rate_limit_group_dpr;
        if (!analyse_only){
            rate_limit_individual.execute_individual_probes4(probes_infos, custom_rates, output_dir_individual);
            // Group probing same rate
            std::cout << "Proceeding to probing groups phase with same probing rate\n";
            rate_limit_group.execute_group_probes4(probes_infos, custom_rates, "GROUPSPR", output_dir_groups);
            std::cout << "Proceeding to probing groups phase with different probing rate\n";
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
            rate_limit_group_dpr.execute_group_probes4(probes_infos, custom_rates, "GROUPDPR", output_dir_groups);
        }
        // Analysis
        if(!probe_only){
            auto individual_ostream = rate_limit_individual.analyse_individual_probes4(probes_infos, custom_rates, output_dir_individual);
            ostream << individual_ostream.str();
            auto group_spr_ostream = rate_limit_group.analyse_group_probes4(probes_infos, custom_rates, "GROUPSPR", output_dir_groups);
            ostream << group_spr_ostream.str();
            auto group_dpr_ostream = rate_limit_group_dpr.analyse_group_probes4(probes_infos, custom_rates, "GROUPDPR", output_dir_groups);
            ostream << group_dpr_ostream.str();
            std::stringstream file_name;

            for (const auto & probe_infos: probes_infos){
                file_name << "_" << probe_infos.get_real_target4();
            }
            std::ofstream outfile (file_name.str());
            outfile << ostream.str() << "\n";
        }


    } else if (probes_infos[0].get_family() == PDU::PDUType::IPv6){
        rate_limit_individual_t rate_limit_individual;
        rate_limit_group_t rate_limit_group;
        rate_limit_group_t rate_limit_group_dpr;
        if (!analyse_only){
            rate_limit_individual.execute_individual_probes6(probes_infos, custom_rates, output_dir_individual);
            // Group probing same rate
            std::cout << "Proceeding to probing groups phase with same probing rate\n";
            rate_limit_group.execute_group_probes6(probes_infos, custom_rates, "GROUPSPR", output_dir_groups);
            std::cout << "Proceeding to probing groups phase with different probing rate\n";
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
            rate_limit_group_dpr.execute_group_probes6(probes_infos, custom_rates, "GROUPDPR", output_dir_groups);
        }
        // Analysis
        if(!probe_only){
            auto individual_ostream = rate_limit_individual.analyse_individual_probes6(probes_infos, custom_rates, output_dir_individual);
            ostream << individual_ostream.str();
            auto group_spr_ostream = rate_limit_group.analyse_group_probes6(probes_infos, custom_rates, "GROUPSPR", output_dir_groups);
            ostream << group_spr_ostream.str();
            auto group_dpr_ostream = rate_limit_group_dpr.analyse_group_probes6(probes_infos, custom_rates, "GROUPDPR", output_dir_groups);
            ostream << group_dpr_ostream.str();
            std::stringstream file_name;

            for (const auto & probe_infos: probes_infos){
                file_name << "_" << probe_infos.get_real_target6();
            }
            std::ofstream outfile (file_name.str());
            outfile << ostream.str() << "\n";
        }
    }

    std::cout << ostream.str();

}

