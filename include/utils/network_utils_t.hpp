//
// Created by System Administrator on 02/12/2018.
//

#ifndef ICMPRATELIMITING_NETWORK_UTILS_T_HPP
#define ICMPRATELIMITING_NETWORK_UTILS_T_HPP


#include <tins/tins.h>
#include <unordered_map>


namespace utils{
    bool compute_next_probing_rate(double loss_rate,
                                   const std::string & real_target,
                                   std::map<int, double> & loss_rate_by_probing_rate,
                                   int & probing_rate,
                                   int starting_probing_rate,
                                   std::unordered_map<std::string, int> & triggering_rates,
                                   const std::pair<double, double> & target_loss_rate_interval,
                                   bool & is_binary_search,
                                   int & binary_search_iteration
    );

    int find_triggering_rate(const probe_infos_t & probe_infos,
                             const std::vector<probe_infos_t> & probes_infos,
                             int starting_probing_rate,
                              const std::pair<double, double> & target_loss_rate_interval,
                              const std::string & output_dir,
                              const std::string & probing_type,
                              std::unordered_map<std::string, int> & triggering_rates);

    int find_closest_rate(const probe_infos_t & first_candidate_probe_infos,
                          const std::map<int, double> & loss_rate_by_probing_rate,
                          const std::pair<double, double> & target_loss_rate_interval);


    static auto maximum_probing_rate = std::pow(2, 16) - 1;
    static auto minimum_probing_rate = 512;

    static auto maximum_binary_search_iteration = 8;
    static auto measurement_time = 5;
}


#endif //ICMPRATELIMITING_NETWORK_UTILS_T_HPP
