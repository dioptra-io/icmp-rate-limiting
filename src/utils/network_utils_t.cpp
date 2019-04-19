//
// Created by System Administrator on 02/12/2018.
//
#include <iostream>
#include <rate_limit_analyzer_t.hpp>
#include <utils/file_utils_t.hpp>
#include <probe_infos_t.hpp>
#include <algorithm_context_t.hpp>
#include "../../include/utils/network_utils_t.hpp"

using namespace Tins;

namespace utils{
    bool compute_next_probing_rate(double loss_rate,
                                  const std::string & real_target,
                                  std::map<int, double> & loss_rate_by_probing_rate,
                                  int & probing_rate,
                                  int starting_probing_rate,
                                  std::unordered_map<std::string, int> & triggering_rates,
                                  const std::pair<double, double> & target_loss_rate_interval,
                                  bool & is_binary_search,
                                  int & binary_search_iteration,
                                  double exponential_reason
                                  ){
        auto lower_bound_loss_rate = target_loss_rate_interval.first;
        auto upper_bound_loss_rate = target_loss_rate_interval.second;
        std::cout << "Loss rate: " << loss_rate << "\n";

        loss_rate_by_probing_rate[probing_rate] = loss_rate;

        if (loss_rate == 1 && probing_rate == starting_probing_rate) {
            // Unresponsive
            std::cout << real_target << " is unresponsive \n";
            triggering_rates[real_target] = starting_probing_rate;
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
                probing_rate *= exponential_reason;
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

    int find_closest_rate(const probe_infos_t & first_candidate_probe_infos,
                          const std::map<int, double> & loss_rate_by_probing_rate,
                          const std::pair<double, double> & target_loss_rate_interval){
        auto closest_difference_loss_rate = 1.0;
        auto closest_probing_rate = 0;
        for (const auto & probing_rate_loss_rate: loss_rate_by_probing_rate){
            auto loss_rate = probing_rate_loss_rate.second;
            if (loss_rate > target_loss_rate_interval.second){
                auto difference_loss_rate = loss_rate - target_loss_rate_interval.second;
                if (difference_loss_rate < closest_difference_loss_rate){
                    closest_difference_loss_rate = difference_loss_rate;
                    closest_probing_rate = probing_rate_loss_rate.first;
                }
            } else {
                auto difference_loss_rate = target_loss_rate_interval.first - loss_rate;
                if (difference_loss_rate < closest_difference_loss_rate){
                    closest_difference_loss_rate = difference_loss_rate;
                    closest_probing_rate = probing_rate_loss_rate.first;
                }
            }
        }
        return closest_probing_rate;
    }

    int find_triggering_rate(const probe_infos_t & probe_infos,
                             const std::vector<probe_infos_t> & probes_infos,
                              int starting_probing_rate,
                              const std::pair<double, double> & target_loss_rate_interval,
                              const std::string & output_dir,
                              const std::string & probing_type,
                              double exponential_reason,
                              algorithm_context_t & algorithm_context){


        auto real_target = probe_infos.get_real_target();
        auto icmp_type = probe_infos.icmp_type_str();


        auto is_binary_search = false;
        auto probing_rate = starting_probing_rate;
        auto binary_search_iteration = 0;
        std::map<int, double> & loss_rate_by_probing_rate = algorithm_context.get_loss_rates_by_ips()[real_target];
        std::unordered_map<std::string, int> & triggering_rates =  algorithm_context.get_triggering_rates_by_ips();
        while (binary_search_iteration < maximum_binary_search_iteration) {
            if (probing_rate >= maximum_probing_rate || probing_rate < starting_probing_rate) {
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
                pcap_file = build_pcap_name(output_dir, icmp_type, real_target, probing_type,
                                            probing_rate);
            }


            // Start the analysis of responsiveness.
            auto rate_limit_analyzer = rate_limit_analyzer_t::build_rate_limit_analyzer_t_from_probe_infos(probes_infos);
            std::cout << "Analyzing " << pcap_file << "\n";
            try {
                rate_limit_analyzer.start(pcap_file);
            } catch (const pcap_error & error) {
                std::cerr << error.what() << "\n";
                if (is_binary_search){
                    ++binary_search_iteration;
                }else {
                    break;
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
                                                                binary_search_iteration,
                                                                exponential_reason);

            if (!continue_analyzing) {
                break;
            }
        }

        auto has_found_triggering_rate = triggering_rates.find(real_target) != triggering_rates.end();
        // In case no triggering rate has been found, take the closest value to the triggering rate of the first candidate
        // If it is the first candidate, take the last probing rate of the binary search.
        if (!has_found_triggering_rate){
            auto closest_probing_rate = find_closest_rate(probe_infos, loss_rate_by_probing_rate, target_loss_rate_interval);
            std::cout << "Took the probing rate that triggered the closest loss rate to the target loss rate interval " << closest_probing_rate << "\n";
            triggering_rates[real_target] = closest_probing_rate;
        }

        return triggering_rates[real_target];
    }

}