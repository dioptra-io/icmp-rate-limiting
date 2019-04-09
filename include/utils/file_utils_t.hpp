//
// Created by System Administrator on 24/07/2018.
//

#ifndef ICMPRATELIMITING_FILE_UTILS_T_HPP
#define ICMPRATELIMITING_FILE_UTILS_T_HPP
#include <vector>
#include <string>
#include <regex>
#include <boost/filesystem.hpp>

#include <tins/tins.h>
#include <unordered_map>

#include "../icmp_trigger_probes_t.hpp"
#include "container_utils_t.hpp"
#include <probe_infos_t.hpp>

namespace utils{

    std::vector<probe_infos_t> parse_input_file(const char * input_file_path);
    std::pair<double, double> parse_loss_rate_interval(const std::string & loss_rate_interval_str);
    std::unordered_map<std::string, int> parse_individual_result_file(const std::string & individual_result_file,
                                                                      const std::pair<double,double> & target_loss_rate_interval);


    std::string build_pcap_name(const std::string & folder,
                                const std::string & icmp_type,
                                const std::string & destination,
                                const std::string & icmp_algo_type,
                                int rate);

    std::stringstream build_output_line(const std::string & address,
                                        const std::string & type,
                                        int probing_rate,
                                        int change_behaviour_rate,
                                        double loss_rate,
                                        double transition_matrix_0_0,
                                        double transition_matrix_0_1,
                                        double transition_matrix_1_0,
                                        double transition_matrix_1_1,
                                        const std::unordered_map<std::string, double> & correlations);

    std::vector<std::string> extract_ips_from_filenames(const boost::filesystem::path & pcap_directory);

    std::vector<icmp_trigger_probes_t> build_icmp_trigger_probes_from_file(const std::string &file_name,
                                                                           const Tins::IPv4Address &source);

}

#endif //ICMPRATELIMITING_FILE_UTILS_T_HPP
