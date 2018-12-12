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
                               const std::string & output_dir_group );

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

    int compute_rate_factor_dpr(int before_triggering_rate, int triggering_rate, int n_ip);
    int compute_probing_rate(int base_probing_rate, const std::vector<probe_infos_t> & groups);
};


#endif //ICMPRATELIMITING_RATE_LIMIT_GROUP_T_HPP
