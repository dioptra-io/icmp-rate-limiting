//
// Created by System Administrator on 06/11/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_GROUP_T_HPP
#define ICMPRATELIMITING_RATE_LIMIT_GROUP_T_HPP

#include <sstream>
#include <probe_infos_t.hpp>

class rate_limit_group_t {
public:

    void execute_group_probes4(const std::vector<probe_infos_t> & probes_infos,
                               int probing_rate,
                               const std::pair<double, double> & target_loss_rate_interval,
                               bool   triggering_probing_rate_already_found,
                               const std::string & group_type,
                               const std::string & output_dir_group

    );

    void execute_group_probes4(const Tins::NetworkInterface & sniff_interface,
                               const std::vector<probe_infos_t> & group,
                               int probing_rate,
                               const std::string & group_type,
                               const std::string & output_dir_group );

    std::stringstream analyse_group_probes4(
            const std::vector<probe_infos_t> & group,
            int probing_rate,
            const std::string & group_type,
            const std::string & output_dir_group);

    std::stringstream analyse_group_probes4(
            const std::vector<probe_infos_t> & probes_infos,
            int   starting_probing_rate,
            const std::pair<double, double> & target_loss_interval,
            const std::string & group_type,
            const std::string & output_dir_group);

    void execute_group_probes6(const std::vector<probe_infos_t> & probes_infos,
                               const std::vector<int> & probing_rates,
                               const std::string & group_type,
                               const std::string & output_dir_group

    );

    void execute_group_probes6(const Tins::NetworkInterface & sniff_interface,
                               const std::vector<probe_infos_t> & group,
                               int probing_rate,
                               const std::string & group_type,
                               const std::string & output_dir_group );

    std::stringstream analyse_group_probes6(
            const std::vector<probe_infos_t> & group,
            int probing_rate,
            const std::string & group_type,
            const std::string & output_dir_group);

    std::stringstream analyse_group_probes6(
            const std::vector<probe_infos_t>& groups,
            const std::vector<int> & probing_rates,
            const std::string & group_type,
            const std::string & output_dir_group);


private:

    int compute_rate_factor_dpr(int probing_rate, int n_ip);
    int compute_probing_rate(int base_probing_rate, const std::vector<probe_infos_t> & groups);
};


#endif //ICMPRATELIMITING_RATE_LIMIT_GROUP_T_HPP
