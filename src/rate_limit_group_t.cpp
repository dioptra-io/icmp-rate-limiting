//
// Created by System Administrator on 06/11/2018.
//


#include "../include/rate_limit_group_t.hpp"
#include <tins/tins.h>
#include <unordered_map>

#include <utils/file_utils_t.hpp>
#include <utils/network_utils_t.hpp>
#include <utils/variant_utils_t.hpp>
#include <rate_limit_analyzer_t.hpp>
#include <rate_limit_test_t.hpp>
#include <algorithm_context_t.hpp>
#include <boost/variant.hpp>


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

void rate_limit_group_t::execute_group_probes(const NetworkInterface & sniff_interface,
                           const std::vector<probe_infos_t> & group,
                           int probing_rate,
                           const std::string & group_type,
                           const std::string & output_dir_group ){

    auto nb_probes = measurement_time * probing_rate;
    auto icmp_type = group[0].icmp_type_str();

    rate_limit_test_t rate_limit_test(nb_probes, probing_rate, sniff_interface, group);

    auto pcap_file_name = build_pcap_name(output_dir_group, icmp_type, to_file_name(group, '_'),
                                          group_type,
                                          probing_rate);
    rate_limit_test.set_pcap_file(pcap_file_name);

    std::cout << "Starting " << icmp_type << " for " << pcap_file_name << " with probing rate "
              << probing_rate << "...\n";
    rate_limit_test.start();

}

void rate_limit_group_t::execute_group_probes(const std::vector<probe_infos_t> & probes_infos,
                                               const std::pair<double, double> & target_loss_rate_interval,
                                               const std::string & group_type,
                                               const options_t   & options,
                                               algorithm_context_t & algorithm_context

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

    std::unordered_map<std::string, int> triggering_rates;


    for (const auto & id_group: groups){
        const auto & group = id_group.second;
        auto probing_rate = 0;
        if (algorithm_context.is_triggering_rate_already_found()){
            if (algorithm_context.is_triggering_rate_found_by_group()){
                probing_rate = algorithm_context.get_triggering_rate();
            } else {
                probing_rate = compute_probing_rate(algorithm_context.get_triggering_rate(), group);
            }
        } else {
            if (options.use_individual_for_analyse){

                probing_rate = find_triggering_rate(group[0], group, minimum_probing_rate, target_loss_rate_interval,
                        options.pcap_dir_individual, "INDIVIDUAL", triggering_rates);
                algorithm_context.set_triggering_rate(probing_rate);
                algorithm_context.set_triggering_rate_already_found(true);

                probing_rate = compute_probing_rate(probing_rate, group);




            } else if (options.use_group_for_analyse){
                probing_rate = compute_probing_rate(minimum_probing_rate, group);
            }

        }


        boost::variant<IPv4Address, IPv6Address> real_target;
        if (group[0].get_family() == PDU::PDUType ::IP){
            real_target = group[0].get_real_target4();
        }
        else if (group[0].get_family() == PDU::PDUType ::IPv6){
            real_target = group[0].get_real_target6();
        }

        auto real_target_str = boost::apply_visitor(visitor_t<to_string_functor_t>(to_string_functor_t()), real_target);

        auto is_binary_search = false;
        auto binary_search_iteration = 0;
        std::map<int, double> loss_rate_by_probing_rate;

        while(binary_search_iteration < maximum_binary_search_iteration) {

            if (probing_rate >= maximum_probing_rate || probing_rate < minimum_probing_rate) {
                std::cout << "No triggering probing rate found for the target loss rate interval ["
                          << target_loss_rate_interval.first
                          << ", " << target_loss_rate_interval.second << "] for " << real_target_str << "\n";
                break;
            }


            if (group_type == "GROUPDPR") {
                // Group probing different rate
                // Select the rate so the sum of the group is lower than the individual triggering rate.
                // The triggering rate is the rate before the probing rate if already found

                auto n_candidates = std::count_if(probes_infos.begin(), probes_infos.end(), [](const auto & probe_infos){
                    return probe_infos.get_interface_type() == interface_type_t::CANDIDATE;
                });

                auto ratio_rate = compute_rate_factor_dpr(minimum_probing_rate, probing_rate, n_candidates);
                // Change the rate of 1 candidate by ratio_rate
                group_t group_different_rates(group.begin(), group.end());
                for (auto &probe_infos: group_different_rates) {
                    if (probe_infos.get_interface_type() == interface_type_t::CANDIDATE) {
                        probe_infos.set_probing_rate(ratio_rate);
                        break;
                    }
                }
                execute_group_probes(sniff_interface, group_different_rates, probing_rate, group_type, options.pcap_dir_groups);
            }
            else if (group_type == "GROUPSPR"){
                execute_group_probes(sniff_interface, group, probing_rate, group_type, options.pcap_dir_groups);
            }

            if (algorithm_context.is_triggering_rate_already_found()){
                break;
            } else {

                auto icmp_type = group[0].icmp_type_str();

                auto rate_limit_analyzer = rate_limit_analyzer_t::build_rate_limit_analyzer_t_from_probe_infos(probes_infos);

                auto pcap_file = build_pcap_name(options.pcap_dir_groups, icmp_type, to_file_name(group, '_'),
                                                 group_type,
                                                 probing_rate);

                rate_limit_analyzer.start(pcap_file);

                algorithm_context.get_analyzed_pcap_file()[pcap_file] = std::make_unique<rate_limit_analyzer_t>(rate_limit_analyzer);

                auto loss_rate = rate_limit_analyzer.compute_loss_rate(real_target_str);
                bool continue_probing = compute_next_probing_rate(loss_rate,
                                                                  real_target_str,
                                                                  loss_rate_by_probing_rate,
                                                                  probing_rate,
                                                                  minimum_probing_rate,
                                                                  triggering_rates,
                                                                  target_loss_rate_interval,
                                                                  is_binary_search,
                                                                  binary_search_iteration);

                if (!continue_probing){
                    break;
                }

            }
            std::this_thread::sleep_for(std::chrono::seconds(measurement_time + 1));
        }
        if (!algorithm_context.is_triggering_rate_already_found()){
            algorithm_context.set_triggering_rate(probing_rate);
            algorithm_context.set_triggering_rate_found_by_group(true);
        }
        std::this_thread::sleep_for(std::chrono::seconds(measurement_time + 1));
    }
    algorithm_context.set_triggering_rate_already_found(true);
}



std::stringstream rate_limit_group_t::analyse_group_probes(
        const std::vector<probe_infos_t> & group,
        int probing_rate,
        const std::string & group_type,
        const std::string & output_dir_group,
        algorithm_context_t & algorithm_context){

    std::stringstream ostream;

    std::unordered_map<std::string, double> loss_rates;


    auto rate_limit_analyzer = rate_limit_analyzer_t::build_rate_limit_analyzer_t_from_probe_infos(group);

    auto pcap_file = build_pcap_name(output_dir_group, group[0].icmp_type_str(), to_file_name(group, '_'),
                                     group_type,
                                     probing_rate);

    std::cout << "Analyzing " << pcap_file << "\n";

    auto it = algorithm_context.get_analyzed_pcap_file().find(pcap_file);
    if ( it != algorithm_context.get_analyzed_pcap_file().end()){
        rate_limit_analyzer = *(it->second);
    }
    else {
        // Start the analysis of responsiveness.
        rate_limit_analyzer.start(pcap_file);
        algorithm_context.get_analyzed_pcap_file()[pcap_file] = std::make_unique<rate_limit_analyzer_t> (rate_limit_analyzer);
    }

    std::unordered_map<std::pair<std::string, std::string>, double, pairhash> correlations;

    // Extract correlation

    if (group_type == "GROUPSPR") {


//        for (int i = 0; i < group.size(); ++i) {
//            auto ip_address_i = group[i].get_real_target();
//            for (int j = i; j < group.size(); ++j) {
//                auto ip_address_j = group[j].get_real_target();
//                auto correlation = rate_limit_analyzer.correlation(ip_address_i, ip_address_j);
//                correlations[std::make_pair(ip_address_i, ip_address_j)] = correlation;
//                correlations[std::make_pair(ip_address_j, ip_address_i)] = correlation;
//            }
//        }

    }

    else if (group_type == "GROUPDPR"){
        // First candidate is the high rate one
        auto ip_address_high_rate = group[0].get_real_target();
        for (int i = 1; i < group.size(); ++i) {
            auto ip_address_i = group[i].get_real_target();
            auto correlation = rate_limit_analyzer.correlation_high_low(ip_address_high_rate, ip_address_i);
            correlations[std::make_pair(ip_address_high_rate, ip_address_i)] = correlation;
            correlations[std::make_pair(ip_address_i, ip_address_high_rate)] = correlation;
        }
    }

    // Now extract per interface infos.
    for (const auto &probe_info : group) {
        auto real_target = probe_info.get_real_target();
        auto loss_rate = rate_limit_analyzer.compute_loss_rate(real_target);
        std::cout << real_target << " loss rate: " << loss_rate << "\n";

        // Changing behaviour time
        auto change_point = rate_limit_analyzer.compute_icmp_change_point(real_target);

        // Transition matrices
        auto transition_matrix = rate_limit_analyzer.compute_loss_model(real_target);

        // Extract the relevant correlations
        // Per ip correlation
        std::unordered_map<std::string, double> correlations_map;
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


void rate_limit_group_t::analyse_group_probes(
        const std::vector<probe_infos_t> & probes_infos,
        const std::pair<double, double> & target_loss_interval,
        const std::string & group_type,
        const options_t & options,
        algorithm_context_t & algorithm_context) {


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

    std::unordered_map<std::string, int> triggering_rates;

    auto triggering_rate = 0;

    for (const auto & group : groups){
        const auto & probe_infos = group.second[0];

        if (algorithm_context.is_triggering_rate_already_found()){
            triggering_rate = algorithm_context.get_triggering_rate();
            if (!options.group_only){
                triggering_rate = compute_probing_rate(triggering_rate, group.second);
            }
        }
        else {
            // We are in analyse only phase
            if (options.use_group_for_analyse){
                auto starting_probing_rate = compute_probing_rate(minimum_probing_rate, group.second);
                triggering_rate = find_triggering_rate(probe_infos,probes_infos, starting_probing_rate, target_loss_interval, options.pcap_dir_groups, group_type, triggering_rates);
                algorithm_context.set_triggering_rate_found_by_group(true);
            } else if (options.use_individual_for_analyse){
                triggering_rate = find_triggering_rate(probe_infos,probes_infos, minimum_probing_rate, target_loss_interval, options.pcap_dir_individual, "INDIVIDUAL", triggering_rates);
                triggering_rate = compute_probing_rate(triggering_rate, group.second);
            }
            algorithm_context.set_triggering_rate(triggering_rate);
        }

        try{
            algorithm_context.get_ostream() << analyse_group_probes(group.second, triggering_rate, group_type, options.pcap_dir_groups, algorithm_context).str();
        } catch (const pcap_error & e){
            std::cerr << e.what() << "\n";
        }
    }
    algorithm_context.set_triggering_rate_already_found(true);
}


int rate_limit_group_t::compute_rate_factor_dpr(int before_triggering_rate, int triggering_rate, int ip_n){

    auto low_rate = before_triggering_rate / ip_n;

    auto rate_factor = static_cast<int>(triggering_rate / low_rate);


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
