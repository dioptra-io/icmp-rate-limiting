//
// Created by System Administrator on 06/11/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_GROUP_T_HPP
#define ICMPRATELIMITING_RATE_LIMIT_GROUP_T_HPP

#include <sstream>
#include <probe_infos_t.hpp>
#include <algorithm_context_t.hpp>

class rate_limit_group_t {
public:



    void execute_group_probes(const Tins::NetworkInterface & sniff_interface,
                               const std::vector<probe_infos_t> & group,
                               int probing_rate,
                               const std::string & group_type,
                               const std::string & output_dir_group,
                               int measurement_time );

    void execute_group_probes(const std::vector<probe_infos_t> & probes_infos,
                               const std::pair<double, double> & target_loss_rate_interval,
                               const std::string & group_type,
                               const utils::options_t & options,
                               algorithm_context_t & algorithm_context
    );

    std::stringstream analyse_group_probes(
            const std::vector<probe_infos_t> & group,
            int probing_rate,
            const std::string & group_type,
            const std::string & output_dir_group,
            algorithm_context_t & algorithm_context);

    void analyse_group_probes(
            const std::vector<probe_infos_t> & probes_infos,
            const std::pair<double, double> & target_loss_interval,
            const std::string & group_type,
            const utils::options_t & options,
            algorithm_context_t & algorithm_context);



private:
    /**
     * Gives the rate factor between the first candidate and the other candidate
     * @param algorithm_context
     * @return
     */
    int compute_low_rate_dpr(const probe_infos_t &first_candidate, const probe_infos_t &other_candidate,
                             algorithm_context_t &algorithm_context) const ;
    int compute_rate_factor_dpr(std::vector<probe_infos_t> &candidates, algorithm_context_t &algorithm_context, const utils::options_t &) const;

    int compute_probing_rate(int base_probing_rate, const std::vector<probe_infos_t> & groups, algorithm_context_t & algorithm_context) const;
};


#endif //ICMPRATELIMITING_RATE_LIMIT_GROUP_T_HPP
