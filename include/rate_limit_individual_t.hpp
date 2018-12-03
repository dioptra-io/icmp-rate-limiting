//
// Created by System Administrator on 06/11/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_INDIVIDUAL_T_HPP
#define ICMPRATELIMITING_RATE_LIMIT_INDIVIDUAL_T_HPP

#include <tins/tins.h>
#include <probe_infos_t.hpp>

class rate_limit_individual_t {
public:
    void execute_individual_probes4(
            const Tins::NetworkInterface &sniff_interface,
            const probe_infos_t &probe_infos,
            int probing_rate,
            const std::string &output_dir_individual);

    /**
     *
     * @param probes_infos
     * @param starting_probing_rate
     * @param target_loss_rate
     * @param output_dir_individual
     * @return the max probing rate among the candidates that triggered target_loss_rate
     */
    int execute_individual_probes4(
            const std::vector<probe_infos_t> &probes_infos,
            int   starting_probing_rate,
            const std::pair<double, double> &target_loss_rate_interval,
            const std::string &output_dir_individual);

    std::stringstream analyse_individual_probes4(const std::vector <probe_infos_t> & probes_infos,
                                                 int starting_probing_rate,
                                                 const std::pair<double, double> & target_loss_rate_interval,
                                                 const std::string & output_dir_individual);

    std::stringstream analyse_individual_probes4(
            const probe_infos_t &probe_infos,
            int probing_rate,
            const std::string & pcap_file);

    void execute_individual_probes6(
            const Tins::NetworkInterface &sniff_interface,
            const probe_infos_t &probe_infos,
            int probing_rate,
            const std::string &output_dir_individual);

    void execute_individual_probes6(
            const std::vector<probe_infos_t> &probes_infos,
            const std::vector<int> &probing_rates,
            const std::string &output_dir_individual);

    std::stringstream analyse_individual_probes6(const std::vector<probe_infos_t> &probes_infos,
                                                 const std::vector<int> &probing_rates,
                                                 const std::string &output_dir_individual);

    std::stringstream analyse_individual_probes6(
            const probe_infos_t &probe_infos,
            int probing_rate,
            const std::string & pcap_file);
};


#endif //ICMPRATELIMITING_RATE_LIMIT_INDIVIDUAL_T_HPP
