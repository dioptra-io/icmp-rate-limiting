//
// Created by System Administrator on 22/10/2018.
//
#include <string>
#include <rate_limit_analyzer_t.hpp>
#include <utils/container_utils_t.hpp>

using namespace Tins;
using namespace utils;
/**
 * This binary just serialize in a json list format the responsiveness of an interface
 * @param argc
 * @param argv
 * @return
 */

int main (int argc, char **argv){


    std::string pcap_file {argv[1]};

    rate_limit_analyzer_t analyzer {utils::probing_style_t::DIRECT, Tins::PDU::IP};

    analyzer.start(pcap_file);

    std::cout << analyzer.serialize_raw4() << "\n";

}