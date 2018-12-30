//
// Created by System Administrator on 04/12/2018.
//

#ifndef ICMPRATELIMITING_ALGORITHM_CONTEXT_T_HPP
#define ICMPRATELIMITING_ALGORITHM_CONTEXT_T_HPP


#include <unordered_map>
#include <rate_limit_analyzer_t.hpp>
#include <sstream>

class algorithm_context_t {

public:

    algorithm_context_t(const std::vector<probe_infos_t> & probes_infos);

    std::unordered_map<std::string, std::unique_ptr<rate_limit_analyzer_t>> & get_analyzed_pcap_file();


    std::unordered_map<std::string, std::map<int, double>> & get_loss_rates_by_ips();

    std::unordered_map<std::string, int> & get_triggering_rates_by_ips();

    bool is_triggering_rate_already_found() const;

    bool is_triggering_rate_found_by_group() const;

    void set_triggering_rate_found_by_group(bool triggering_rate_found_by_group);

    void set_triggering_rate_already_found(bool triggering_rate_already_found);

    std::stringstream & get_ostream();

private:
    std::unordered_map<std::string, std::unique_ptr<rate_limit_analyzer_t> > analyzed_pcap_file;
    bool triggering_rate_already_found = false;
    bool triggering_rate_found_by_group = false;
    std::unordered_map<std::string, std::map<int, double>> loss_rates_by_ips;
    std::unordered_map<std::string, int> triggering_rates_by_ips;
    std::stringstream ostream;

};


#endif //ICMPRATELIMITING_ALGORITHM_CONTEXT_T_HPP
