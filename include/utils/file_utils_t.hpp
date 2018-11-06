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
namespace utils{
    std::string build_pcap_name(const std::string & folder,
                                const std::string & icmp_type,
                                const std::string & destination,
                                const std::string & icmp_algo_type,
                                int rate);

    template <typename Address>
    std::stringstream build_output_line(const Address & address,
                                        const std::string & type,
                                        int probing_rate,
                                        int change_behaviour_rate,
                                        double loss_rate,
                                        double transition_matrix_0_0,
                                        double transition_matrix_0_1,
                                        double transition_matrix_1_0,
                                        double transition_matrix_1_1,
                                        const std::unordered_map<Address, double> correlations){

        std::stringstream ostream;
        ostream << address << ", " << type << ", " << probing_rate << ", " <<  change_behaviour_rate << ", " << loss_rate <<", ";
        ostream << transition_matrix_0_0 << ", "  << transition_matrix_0_1  << ", " << transition_matrix_1_0 << ", " << transition_matrix_1_1;
        if (type == std::string("GROUPSPR")){
            for (const auto & correlation_address : correlations){
                ostream << ", " << correlation_address.first << ": " << correlation_address.second;
            }
        }

        ostream << "\n";


        return ostream;
    }

    std::vector<std::string> extract_ips_from_filenames(const boost::filesystem::path & pcap_directory);

    std::vector<icmp_trigger_probes_t> build_icmp_trigger_probes_from_file(const std::string &file_name,
                                                                           const Tins::IPv4Address &source);
}

#endif //ICMPRATELIMITING_FILE_UTILS_T_HPP
