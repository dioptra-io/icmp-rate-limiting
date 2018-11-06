//
// Created by System Administrator on 06/11/2018.
//


#include "../include/rate_limit_group_t.hpp"
#include <tins/tins.h>
#include <unordered_map>

#include <utils/file_utils_t.hpp>
#include <rate_limit_analyzer_t.hpp>
#include <rate_limit_test_t.hpp>


using namespace Tins;
using namespace utils;

namespace{
    struct pairhash {
    public:
        template <typename T, typename U>
        std::size_t operator()(const std::pair<T, U> &x) const
        {
            return std::hash<T>()(x.first) ^ std::hash<U>()(x.second);
        }
    };
}

void rate_limit_group_t::execute_group_probes4(const NetworkInterface & sniff_interface,
                           const std::vector<probe_infos_t> & group,
                           int probing_rate,
                           const std::string & group_type,
                           const std::string & output_dir_group ){

    probing_rate *= group.size();

    auto nb_probes = 5 * probing_rate;
    auto icmp_type = group[0].icmp_type_str();

    rate_limit_test_t<IPv4Address> rate_limit_test(nb_probes, probing_rate, sniff_interface, group);

    auto pcap_file_name = build_pcap_name(output_dir_group, icmp_type, to_file_name(group, '_'),
                                          group_type,
                                          probing_rate);
    rate_limit_test.set_pcap_file(pcap_file_name);

    std::cout << "Starting " << icmp_type << " for " << pcap_file_name << " with probing rate "
              << probing_rate << "...\n";
    rate_limit_test.start();

}

void rate_limit_group_t::execute_group_probes4(const std::vector<probe_infos_t> & probes_infos,
                           const std::vector<int> & probing_rates,
                           const std::string & group_type,
                           const std::string & output_dir_group

){
    /**
     * Build groups from probes_infos
     */

    std::cout << "Building groups for probing...\n";
    using group_t = std::vector<probe_infos_t>;
    std::unordered_map<int, group_t> groups;
    std::for_each(probes_infos.begin(), probes_infos.end(), [&groups](const probe_infos_t &probe_info) {
        auto group_id = probe_info.get_group_id();
        auto has_key = groups.find(group_id);
        if (has_key == groups.end()) {
            groups[group_id] = std::vector<probe_infos_t>();
        }
        groups[group_id].push_back(probe_info);
    });
    std::cout << "Finished building groups\n";


    /**
     * Start probing
     */
    auto sniff_interface = NetworkInterface::default_interface();


    for (const auto & id_group: groups){
        const auto & group = id_group.second;
        for (const auto probing_rate : probing_rates){
            execute_group_probes4(sniff_interface, group, probing_rate, group_type, output_dir_group);
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }

    }

}



std::stringstream rate_limit_group_t::analyse_group_probes4(
        const std::vector<probe_infos_t> & group,
        int probing_rate,
        const std::string & group_type,
        const std::string & output_dir_group){

    std::stringstream ostream;

    std::unordered_map<IPv4Address, double> loss_rates;


    auto icmp_type = group[0].icmp_type_str();
    std::unordered_map<IPv4Address, IP> matchers;
    probing_style_t probing_style = group[0].get_probing_style();
    for (const auto &probe_info : group) {
        // Prepare the analysis
        matchers.insert(std::make_pair(probe_info.get_real_target4(), probe_info.get_packet4()));
    }


    auto pcap_file = build_pcap_name(output_dir_group, icmp_type, to_file_name(group, '_'),
                                     group_type,
                                     static_cast<int>(group.size() * probing_rate));

    rate_limit_analyzer_t rate_limit_analyzer(probing_style, matchers);


    // Start the analysis of responsiveness.
    rate_limit_analyzer.start(pcap_file);


    std::unordered_map<std::pair<IPv4Address, IPv4Address>, double, pairhash> correlations;

    // Per ip correlation
    std::unordered_map<IPv4Address, double> correlations_map;
    // Extract correlation

    if (group_type == "GROUPSPR") {


        for (int i = 0; i < group.size(); ++i) {
            for (int j = i; j < group.size(); ++j) {
                auto ip_address_i = group[i].get_real_target4();
                auto ip_address_j = group[j].get_real_target4();
                auto correlation = rate_limit_analyzer.correlation4(ip_address_i, ip_address_j);
                correlations[std::make_pair(ip_address_i, ip_address_j)] = correlation;
                correlations[std::make_pair(ip_address_j, ip_address_i)] = correlation;
            }
        }

    }

    // Now extract per interface infos.
    for (const auto &probe_info : group) {
        auto real_target = probe_info.get_real_target4();
        auto loss_rate = rate_limit_analyzer.compute_loss_rate(probe_info.get_real_target4());
        std::cout << probe_info.get_real_target4() << " loss rate: " << loss_rate << "\n";

        // Changing behaviour time
        auto changing_behaviour_time = rate_limit_analyzer.compute_icmp_triggering_rate4(real_target);

        // Transition matrices
        auto transition_matrix = rate_limit_analyzer.compute_loss_model4(real_target);

        // Extract the relevant correlations

        for (const auto &correlation : correlations) {
            auto address1 = correlation.first.first;
            auto address2 = correlation.first.second;

            auto correlation_1_2 = correlation.second;
            if (address1 == real_target) {
                correlations_map[address2] = correlation_1_2;
            }
        }

        auto line_stream = build_output_line(
                real_target,
                group_type,
                static_cast<int>(group.size() * probing_rate),
                changing_behaviour_time.first,
                loss_rate,
                transition_matrix.transition(0,0),
                transition_matrix.transition(0,1),
                transition_matrix.transition(1,0),
                transition_matrix.transition(1,1),
                correlations_map);
        ostream << line_stream.str();

    }

    return ostream;
}


std::stringstream rate_limit_group_t::analyse_group_probes4(
        const std::vector<probe_infos_t> & probes_infos,
        const std::vector<int> & probing_rates,
        const std::string & group_type,
        const std::string & output_dir_group) {

    std::stringstream ostream;

    std::cout << "Building groups for analyzing...\n";
    using group_t = std::vector<probe_infos_t>;
    std::unordered_map<int, group_t> groups;
    std::for_each(probes_infos.begin(), probes_infos.end(), [&groups](const probe_infos_t &probe_info) {
        auto group_id = probe_info.get_group_id();
        auto has_key = groups.find(group_id);
        if (has_key == groups.end()) {
            groups[group_id] = std::vector<probe_infos_t>();
        }
        groups[group_id].push_back(probe_info);
    });
    std::cout << "Finished building groups\n";


    for (const auto & group : groups){
        for (const auto probing_rate : probing_rates){
            ostream << analyse_group_probes4(group.second, probing_rate, group_type, output_dir_group).str();
        }

    }
    return ostream;
}


void rate_limit_group_t::execute_group_probes6(const NetworkInterface & sniff_interface,
                                               const std::vector<probe_infos_t> & group,
                                               int probing_rate,
                                               const std::string & group_type,
                                               const std::string & output_dir_group ){

    probing_rate *= group.size();

    auto nb_probes = 5 * probing_rate;
    auto icmp_type = group[0].icmp_type_str();

    rate_limit_test_t<IPv6Address> rate_limit_test(nb_probes, probing_rate, sniff_interface, group);

    auto pcap_file_name = build_pcap_name(output_dir_group, icmp_type, to_file_name(group, '_'),
                                          group_type,
                                          probing_rate);
    rate_limit_test.set_pcap_file(pcap_file_name);

    std::cout << "Starting " << icmp_type << " for " << pcap_file_name << " with probing rate "
              << probing_rate << "...\n";
    rate_limit_test.start();

}

void rate_limit_group_t::execute_group_probes6(const std::vector<probe_infos_t> & probes_infos,
                                               const std::vector<int> & probing_rates,
                                               const std::string & group_type,
                                               const std::string & output_dir_group

){
    /**
     * Build groups from probes_infos
     */

    std::cout << "Building groups for probing...\n";
    using group_t = std::vector<probe_infos_t>;
    std::unordered_map<int, group_t> groups;
    std::for_each(probes_infos.begin(), probes_infos.end(), [&groups](const probe_infos_t &probe_info) {
        auto group_id = probe_info.get_group_id();
        auto has_key = groups.find(group_id);
        if (has_key == groups.end()) {
            groups[group_id] = std::vector<probe_infos_t>();
        }
        groups[group_id].push_back(probe_info);
    });
    std::cout << "Finished building groups\n";


    /**
     * Start probing
     */
    auto sniff_interface = NetworkInterface::default_interface();


    for (const auto & id_group: groups){
        const auto & group = id_group.second;
        for (const auto probing_rate : probing_rates){
            execute_group_probes6(sniff_interface, group, probing_rate, group_type, output_dir_group);
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }

    }

}



std::stringstream rate_limit_group_t::analyse_group_probes6(
        const std::vector<probe_infos_t> & group,
        int probing_rate,
        const std::string & group_type,
        const std::string & output_dir_group){

    std::stringstream ostream;

    std::unordered_map<IPv6Address, double> loss_rates;


    auto icmp_type = group[0].icmp_type_str();
    std::unordered_map<IPv6Address, IPv6> matchers;
    probing_style_t probing_style = group[0].get_probing_style();
    for (const auto &probe_info : group) {
        // Prepare the analysis
        matchers.insert(std::make_pair(probe_info.get_real_target6(), probe_info.get_packet6()));
    }


    auto pcap_file = build_pcap_name(output_dir_group, icmp_type, to_file_name(group, '_'),
                                     group_type,
                                     static_cast<int>(group.size() * probing_rate));

    rate_limit_analyzer_t rate_limit_analyzer(probing_style, matchers);


    // Start the analysis of responsiveness.
    rate_limit_analyzer.start(pcap_file);


    std::unordered_map<std::pair<IPv6Address, IPv6Address>, double, pairhash> correlations;

    // Per ip correlation
    std::unordered_map<IPv6Address, double> correlations_map;
    // Extract correlation

    if (group_type == "GROUPSPR") {


        for (int i = 0; i < group.size(); ++i) {
            for (int j = i; j < group.size(); ++j) {
                auto ip_address_i = group[i].get_real_target6();
                auto ip_address_j = group[j].get_real_target6();
                auto correlation = rate_limit_analyzer.correlation6(ip_address_i, ip_address_j);
                correlations[std::make_pair(ip_address_i, ip_address_j)] = correlation;
                correlations[std::make_pair(ip_address_j, ip_address_i)] = correlation;
            }
        }

    }

    // Now extract per interface infos.
    for (const auto &probe_info : group) {
        auto real_target = probe_info.get_real_target6();
        auto loss_rate = rate_limit_analyzer.compute_loss_rate(probe_info.get_real_target6());
        std::cout << probe_info.get_real_target6() << " loss rate: " << loss_rate << "\n";

        // Changing behaviour time
        auto changing_behaviour_time = rate_limit_analyzer.compute_icmp_triggering_rate6(real_target);

        // Transition matrices
        auto transition_matrix = rate_limit_analyzer.compute_loss_model6(real_target);

        // Extract the relevant correlations

        for (const auto &correlation : correlations) {
            auto address1 = correlation.first.first;
            auto address2 = correlation.first.second;

            auto correlation_1_2 = correlation.second;
            if (address1 == real_target) {
                correlations_map[address2] = correlation_1_2;
            }
        }

        auto line_stream = build_output_line(
                real_target,
                group_type,
                static_cast<int>(group.size() * probing_rate),
                changing_behaviour_time.first,
                loss_rate,
                transition_matrix.transition(0,0),
                transition_matrix.transition(0,1),
                transition_matrix.transition(1,0),
                transition_matrix.transition(1,1),
                correlations_map);
        ostream << line_stream.str();

    }

    return ostream;
}


std::stringstream rate_limit_group_t::analyse_group_probes6(
        const std::vector<probe_infos_t> & probes_infos,
        const std::vector<int> & probing_rates,
        const std::string & group_type,
        const std::string & output_dir_group) {

    std::stringstream ostream;

    std::cout << "Building groups for analyzing...\n";
    using group_t = std::vector<probe_infos_t>;
    std::unordered_map<int, group_t> groups;
    std::for_each(probes_infos.begin(), probes_infos.end(), [&groups](const probe_infos_t &probe_info) {
        auto group_id = probe_info.get_group_id();
        auto has_key = groups.find(group_id);
        if (has_key == groups.end()) {
            groups[group_id] = std::vector<probe_infos_t>();
        }
        groups[group_id].push_back(probe_info);
    });
    std::cout << "Finished building groups\n";


    for (const auto & group : groups){
        for (const auto probing_rate : probing_rates){
            ostream << analyse_group_probes6(group.second, probing_rate, group_type, output_dir_group).str();
        }

    }
    return ostream;
}