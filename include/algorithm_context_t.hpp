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
    std::unordered_map<std::string, std::unique_ptr<rate_limit_analyzer_t>> & get_analyzed_pcap_file();

    int get_triggering_rate() const;

    void set_triggering_rate(int triggering_rate);

    bool is_triggering_rate_already_found() const;

    bool is_triggering_rate_found_by_group() const;

    void set_triggering_rate_found_by_group(bool triggering_rate_found_by_group);

    void set_triggering_rate_already_found(bool triggering_rate_already_found);

    std::stringstream & get_ostream();

private:
    std::unordered_map<std::string, std::unique_ptr<rate_limit_analyzer_t> > analyzed_pcap_file;
    int  triggering_rate = 0;
    bool triggering_rate_already_found = false;
    bool triggering_rate_found_by_group = false;
    std::stringstream ostream;

};


#endif //ICMPRATELIMITING_ALGORITHM_CONTEXT_T_HPP
