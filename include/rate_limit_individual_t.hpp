//
// Created by System Administrator on 06/11/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_INDIVIDUAL_T_HPP
#define ICMPRATELIMITING_RATE_LIMIT_INDIVIDUAL_T_HPP

#include <tins/tins.h>
#include <probe_infos_t.hpp>
#include "algorithm_context_t.hpp"

class rate_limit_individual_t {
public:

    std::stringstream analyse_individual_probes(
            const probe_infos_t &probe_infos,
            int probing_rate,
            const std::string & pcap_file,
            algorithm_context_t & algorithm_context);

    void analyse_individual_probes(const std::vector <probe_infos_t> & probes_infos,
                                    const std::pair<double, double> & target_loss_rate_interval,
                                    const utils::options_t & options,
                                    algorithm_context_t & algorithm_context);


    void execute_individual_probes(
            const Tins::NetworkInterface &sniff_interface,
            const probe_infos_t &probe_infos,
            int probing_rate,
            const std::string &output_dir_individual);

    void execute_individual_probes(
            const  std::vector<probe_infos_t> &probes_infos,
            int    starting_probing_rate,
            const std::pair<double, double> & target_loss_rate_interval,
            const utils::options_t & options,
            algorithm_context_t & algorithm_context);
};


#endif //ICMPRATELIMITING_RATE_LIMIT_INDIVIDUAL_T_HPP
