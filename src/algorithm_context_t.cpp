//
// Created by System Administrator on 04/12/2018.
//

#include <unordered_map>
#include <algorithm_context_t.hpp>


std::unordered_map <std::string, std::unique_ptr<rate_limit_analyzer_t>> & algorithm_context_t::get_analyzed_pcap_file() {
    return analyzed_pcap_file;
}

std::stringstream &algorithm_context_t::get_ostream() {
    return ostream;
}

int algorithm_context_t::get_triggering_rate() const {
    return triggering_rate;
}

bool algorithm_context_t::is_triggering_rate_already_found() const {
    return triggering_rate_already_found;
}

void algorithm_context_t::set_triggering_rate(int triggering_rate) {
    algorithm_context_t::triggering_rate = triggering_rate;
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
