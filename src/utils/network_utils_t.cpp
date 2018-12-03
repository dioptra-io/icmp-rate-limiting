//
// Created by System Administrator on 02/12/2018.
//
#include <iostream>
#include <rate_limit_analyzer_t.hpp>
#include <utils/file_utils_t.hpp>
#include <probe_infos_t.hpp>
#include "../../include/utils/network_utils_t.hpp"

using namespace Tins;

namespace utils{
    bool compute_next_probing_rate(double loss_rate,
                                  const IPv4Address & real_target,
                                  std::map<int, double> & loss_rate_by_probing_rate,
                                  int & probing_rate,
                                  int starting_probing_rate,
                                  std::unordered_map<IPv4Address, int> & triggering_rates,
                                  const std::pair<double, double> & target_loss_rate_interval,
                                  bool & is_binary_search,
                                  int & binary_search_iteration
                                  ){
        auto lower_bound_loss_rate = target_loss_rate_interval.first;
        auto upper_bound_loss_rate = target_loss_rate_interval.second;
        std::cout << "Loss rate: " << loss_rate << "\n";

        loss_rate_by_probing_rate[probing_rate] = loss_rate;

        if (loss_rate == 1 && probing_rate == starting_probing_rate) {
            // Unresponsive
            std::cout << real_target << " is unresponsive \n";
            triggering_rates[real_target] = 0;
            return false;
        }

        if (loss_rate >= target_loss_rate_interval.first && loss_rate <= target_loss_rate_interval.second) {
            // We have found the rate.
            std::cout << "Found the triggering probing rate " << probing_rate
                      << " for the target loss rate interval ["
                    << target_loss_rate_interval.first
                    << ", " << target_loss_rate_interval.second << "] for " << real_target << "\n";
            triggering_rates[real_target] = probing_rate;
            return false;
        }
        if (loss_rate < lower_bound_loss_rate) {
            if (is_binary_search) {
                // Find the upper bound of the loss rate.

                auto upper_bound_it = loss_rate_by_probing_rate.upper_bound(probing_rate);
                auto closest_upper_rate = upper_bound_it->first;
                probing_rate += (closest_upper_rate - probing_rate) / 2;
            } else {
                // RL "slow start"
                probing_rate *= 2;
            }
        } else if (loss_rate > upper_bound_loss_rate) {
            if (!is_binary_search) {
                is_binary_search = true;
            }

            auto element_it = loss_rate_by_probing_rate.find(probing_rate);
            // If the first probing rate is above, stop the measurement
            if (loss_rate_by_probing_rate.size() == 1){
                return false;
            }
            auto just_before_it = std::prev(element_it);
            auto closest_lower_rate = just_before_it->first;
            probing_rate -= (probing_rate - closest_lower_rate) / 2;
        }

        if (is_binary_search){
            binary_search_iteration += 1;
        }
        return true;
    }

    int find_triggering_rate(const probe_infos_t & probe_infos,
                             const std::vector<probe_infos_t> & probes_infos,
                              int starting_probing_rate,
                              const std::pair<double, double> & target_loss_rate_interval,
                              const std::string & output_dir,
                              const std::string & probing_type,
                              std::unordered_map<IPv4Address, int> & triggering_rates){

        const auto & first_candidate_probe_infos = probes_infos[0];
        auto real_target = probe_infos.get_real_target4();
        auto icmp_type = probe_infos.icmp_type_str();



        // Find the probing rate that triggered the target loss rate.
        std::unordered_map<IPv4Address, IP> matchers;
        matchers.insert(std::make_pair(probe_infos.get_real_target4(),
                                       probe_infos.get_packet4()));

        auto is_binary_search = false;
        auto probing_rate = starting_probing_rate;
        auto binary_search_iteration = 0;
        std::map<int, double> loss_rate_by_probing_rate;

        while (binary_search_iteration < maximum_binary_search_iteration) {
            if (probing_rate >= maximum_probing_rate || probing_rate < minimum_probing_rate) {
                std::cout << "No triggering probing rate found for the target loss rate interval ["
                          << target_loss_rate_interval.first
                          << ", " << target_loss_rate_interval.second << "] for " << real_target << "\n";
                break;
            }


            auto pcap_file = std::string();
            if (probing_type == "GROUPDPR" || probing_type == "GROUPSPR"){
                pcap_file = build_pcap_name(output_dir, icmp_type, to_file_name(probes_infos, '_'),
                                probing_type,
                                probing_rate);
            } else if (probing_type == "INDIVIDUAL"){
                pcap_file = build_pcap_name(output_dir, icmp_type, real_target.to_string(), probing_type,
                                            probing_rate);
            }


            // Start the analysis of responsiveness.
            rate_limit_analyzer_t rate_limit_analyzer(probe_infos.get_probing_style(), matchers);
            try {
                rate_limit_analyzer.start(pcap_file);
            } catch (const pcap_error & error) {
                std::cerr << error.what() << "\n";
                if (is_binary_search){
                    ++binary_search_iteration;
                }
                continue;
            }

            auto loss_rate = rate_limit_analyzer.compute_loss_rate(real_target);
            bool continue_analyzing = compute_next_probing_rate(loss_rate,
                                                                real_target,
                                                                loss_rate_by_probing_rate,
                                                                probing_rate,
                                                                starting_probing_rate,
                                                                triggering_rates,
                                                                target_loss_rate_interval,
                                                                is_binary_search,
                                                                binary_search_iteration);

            if (!continue_analyzing) {
                break;
            }
        }

        auto has_found_triggering_rate = triggering_rates.find(real_target) != triggering_rates.end();
        // In case no triggering rate has been found, take the closest value to the triggering rate of the first candidate
        // If it is the first candidate, take the last probing rate of the binary search.
        auto closest_probing_rate = 0;
        if (!has_found_triggering_rate){
            if (probe_infos.get_real_target4() == first_candidate_probe_infos.get_real_target4()){
                closest_probing_rate = probing_rate;
            } else {
                closest_probing_rate = loss_rate_by_probing_rate.lower_bound(triggering_rates[first_candidate_probe_infos.get_real_target4()])->first;
            }
            triggering_rates[real_target] = closest_probing_rate;
        }

        return triggering_rates[real_target];
    }

}