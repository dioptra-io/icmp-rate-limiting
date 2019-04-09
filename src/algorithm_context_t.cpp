//
// Created by System Administrator on 04/12/2018.
//

#include <unordered_map>
#include <algorithm_context_t.hpp>


algorithm_context_t::algorithm_context_t(const std::vector<probe_infos_t> &probes_infos) {
    for (const auto & probe_infos : probes_infos){
        loss_rates_by_ips[probe_infos.get_real_target()] = std::map<int, double>();
    }
}


std::unordered_map <std::string, std::unique_ptr<rate_limit_analyzer_t>> & algorithm_context_t::get_analyzed_pcap_file() {
    return analyzed_pcap_file;
}

std::stringstream &algorithm_context_t::get_ostream() {
    return ostream;
}


bool algorithm_context_t::is_triggering_rate_already_found() const {
    return triggering_rate_already_found;
}

void algorithm_context_t::set_triggering_rate_already_found(bool triggering_rate_already_found) {
    algorithm_context_t::triggering_rate_already_found = triggering_rate_already_found;
}

bool algorithm_context_t::is_triggering_rate_found_by_group() const {
    return triggering_rate_found_by_group;
}

void algorithm_context_t::set_triggering_rate_found_by_group(bool triggering_rate_found_by_group) {
    algorithm_context_t::triggering_rate_found_by_group = triggering_rate_found_by_group;
}

std::unordered_map<std::string, std::map<int, double>> & algorithm_context_t::get_loss_rates_by_ips()  {
    return loss_rates_by_ips;
}

std::unordered_map<std::string, int> & algorithm_context_t::get_triggering_rates_by_ips() {
    return triggering_rates_by_ips;
}

void
algorithm_context_t::set_triggering_rates_by_ips(const std::unordered_map<std::string, int> &triggering_rates_by_ips) {
    algorithm_context_t::triggering_rates_by_ips = triggering_rates_by_ips;
}


