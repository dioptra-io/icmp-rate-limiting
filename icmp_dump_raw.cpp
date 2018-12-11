//
// Created by System Administrator on 22/10/2018.
//
#include <string>
#include <rate_limit_analyzer_t.hpp>
#include <utils/container_utils_t.hpp>
#include <boost/algorithm/string.hpp>

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


    // Parse pcap file to build matchers for analyzer
    std::vector<std::string> tokens;

    boost::split(tokens, pcap_file, [](char c){return c == '_';});

    auto candidate1 = IPv4Address(tokens[4]);
    auto candidate2 = IPv4Address(tokens[5]);
    auto witness = IPv4Address(tokens[6]);
    std::unordered_map<IPv4Address, IP> matchers;
    matchers.insert(std::make_pair(candidate1, IP(candidate1)));
    matchers.insert(std::make_pair(candidate2, IP(candidate2)));
    matchers.insert(std::make_pair(witness, IP(witness)));
    rate_limit_analyzer_t analyzer {utils::probing_style_t::DIRECT, matchers};

    analyzer.start(pcap_file);

    std::cout << analyzer.serialize_raw4() << "\n";



}