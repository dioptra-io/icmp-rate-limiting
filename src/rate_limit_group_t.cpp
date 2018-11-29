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
        for (auto probing_rate : probing_rates){

            probing_rate = compute_probing_rate(probing_rate, group);

            if (group_type == "GROUPDPR") {
                // Group probing different rate
                // Select the rate so the sum of the group is lower than the individual triggering rate.
                auto ratio_rate = compute_rate_factor_dpr(probing_rate, static_cast<int>(probes_infos.size()));
                // Change the rate of 1 candidate by ratio_rate
                group_t group_different_rates(group.begin(), group.end());
                for (auto &probe_infos: group_different_rates) {
                    if (probe_infos.get_interface_type() == interface_type_t::CANDIDATE) {
                        probe_infos.set_probing_rate(ratio_rate);
                        break;
                    }
                }
                execute_group_probes4(sniff_interface, group_different_rates, probing_rate, group_type, output_dir_group);
            }
            else {
                execute_group_probes4(sniff_interface, group, probing_rate, group_type, output_dir_group);
            }

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
                                     probing_rate);

    rate_limit_analyzer_t rate_limit_analyzer(probing_style, matchers);


    // Start the analysis of responsiveness.
    rate_limit_analyzer.start(pcap_file);


    std::unordered_map<std::pair<IPv4Address, IPv4Address>, double, pairhash> correlations;

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

    else if (group_type == "GROUPDPR"){
        // First candidate is the high rate one
        auto ip_address_high_rate = group[0].get_real_target4();
        for (int i = 1; i < group.size(); ++i) {
            auto ip_address_i = group[i].get_real_target4();
            auto correlation = rate_limit_analyzer.correlation_high_low4(ip_address_high_rate, ip_address_i);
            correlations[std::make_pair(ip_address_high_rate, ip_address_i)] = correlation;
            correlations[std::make_pair(ip_address_i, ip_address_high_rate)] = correlation;
        }
    }

    // Now extract per interface infos.
    for (const auto &probe_info : group) {
        auto real_target = probe_info.get_real_target4();
        auto loss_rate = rate_limit_analyzer.compute_loss_rate(probe_info.get_real_target4());
        std::cout << probe_info.get_real_target4() << " loss rate: " << loss_rate << "\n";

        // Changing behaviour time
        auto change_point = rate_limit_analyzer.compute_icmp_change_point4(real_target);

        // Transition matrices
        auto transition_matrix = rate_limit_analyzer.compute_loss_model4(real_target);

        // Extract the relevant correlations
        // Per ip correlation
        std::unordered_map<IPv4Address, double> correlations_map;
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
                probing_rate,
                change_point,
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
        for (auto probing_rate : probing_rates){

            probing_rate = compute_probing_rate(probing_rate, group.second);

            try{
                ostream << analyse_group_probes4(group.second, probing_rate, group_type, output_dir_group).str();
            } catch (const pcap_error & e){
                std::cerr << e.what() << "\n";
            }
        }

    }
    return ostream;
}


void rate_limit_group_t::execute_group_probes6(const NetworkInterface & sniff_interface,
                                               const std::vector<probe_infos_t> & group,
                                               int probing_rate,
                                               const std::string & group_type,
                                               const std::string & output_dir_group ){

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
        for (auto probing_rate : probing_rates){

            probing_rate = compute_probing_rate(probing_rate, group);

            if (group_type == "GROUPDPR") {
                // Group probing different rate
                // Select the rate so the sum of the group is lower than the individual triggering rate.
                auto ratio_rate = compute_rate_factor_dpr(probing_rate, static_cast<int>(probes_infos.size()));
                // Change the rate of 1 candidate by ratio_rate
                group_t group_different_rates(group.begin(), group.end());
                for (auto &probe_infos: group_different_rates) {
                    if (probe_infos.get_interface_type() == interface_type_t::CANDIDATE) {
                        probe_infos.set_probing_rate(ratio_rate);
                        break;
                    }
                }
                execute_group_probes6(sniff_interface, group_different_rates, probing_rate, group_type, output_dir_group);
            }
            else {
                execute_group_probes6(sniff_interface, group, probing_rate, group_type, output_dir_group);
            }
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
                                     probing_rate);

    rate_limit_analyzer_t rate_limit_analyzer(probing_style, matchers);


    // Start the analysis of responsiveness.
    rate_limit_analyzer.start(pcap_file);


    std::unordered_map<std::pair<IPv6Address, IPv6Address>, double, pairhash> correlations;

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

    else if (group_type == "GROUPDPR"){
        // First candidate is the high rate one
        auto ip_address_high_rate = group[0].get_real_target6();
        for (int i = 1; i < group.size(); ++i) {
            auto ip_address_i = group[i].get_real_target6();
            auto correlation = rate_limit_analyzer.correlation_high_low6(ip_address_high_rate, ip_address_i);
            correlations[std::make_pair(ip_address_high_rate, ip_address_i)] = correlation;
            correlations[std::make_pair(ip_address_i, ip_address_high_rate)] = correlation;
        }
    }

    // Now extract per interface infos.
    for (const auto &probe_info : group) {
        auto real_target = probe_info.get_real_target6();
        auto loss_rate = rate_limit_analyzer.compute_loss_rate(probe_info.get_real_target6());
        std::cout << probe_info.get_real_target6() << " loss rate: " << loss_rate << "\n";

        // Changing behaviour time
        auto change_point = rate_limit_analyzer.compute_icmp_change_point6(real_target);

        // Transition matrices
        auto transition_matrix = rate_limit_analyzer.compute_loss_model6(real_target);

        // Extract the relevant correlations
        // Per ip correlation
        std::unordered_map<IPv6Address, double> correlations_map;
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
                probing_rate,
                change_point,
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
        for (auto probing_rate : probing_rates){

            probing_rate = compute_probing_rate(probing_rate, group.second);
            try{
                ostream << analyse_group_probes6(group.second, probing_rate, group_type, output_dir_group).str();
            } catch (const pcap_error & e){
                std::cerr << e.what() << "\n";
            }

        }

    }
    return ostream;
}


int rate_limit_group_t::compute_rate_factor_dpr(int probing_rate, int ip_n){

    // TODO Make this variable according to the individual probing phase.
    // In 99% of the case, the triggering rate is between 1000 and 2000,
    // so taking 1500 * offset_security is sufficient
    auto triggering_rate_threshold = 1500;

    auto low_rate = triggering_rate_threshold / ip_n;

    auto remaining_rate = probing_rate;

    auto rate_factor = static_cast<int>(remaining_rate / low_rate);


    rate_factor = std::max(rate_factor, 2);

    return rate_factor;

}

int rate_limit_group_t::compute_probing_rate(int base_probing_rate, const std::vector<probe_infos_t> & group) {

    // Count the number of candidates and the number of witnesses

    auto n_candidates = 0;
    auto n_witnesses = 0;

    for (const auto & probe_infos : group){
        if (probe_infos.get_interface_type() == interface_type_t::CANDIDATE){
            n_candidates += 1;
        }
        else if (probe_infos.get_interface_type() == interface_type_t::WITNESS){
            n_witnesses += 1;
        }
    }

    // Assuming that the witness is not alias with any of the candidate
    auto probing_rate = static_cast<int>(base_probing_rate + (static_cast<double>(n_witnesses) / n_candidates) * base_probing_rate);

    return probing_rate;
}
