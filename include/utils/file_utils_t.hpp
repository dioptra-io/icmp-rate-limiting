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

#include "../icmp_trigger_probes_t.hpp"
#include "container_utils_t.hpp"

namespace utils{
    std::vector<std::string> extract_ips_from_filenames(const boost::filesystem::path & pcap_directory) {
//        std::regex ipv4_regex {"([0–9]{1,3}\\.){3}\\.([0–9]{1,3})"};
        std::regex ipv4_regex ("([0-9]{1,3}\\.){3}([0-9]{1,3})");

        std::vector<std::string> ips;
        for (boost::filesystem::directory_iterator itr(pcap_directory); itr != boost::filesystem::directory_iterator(); ++itr) {
            // Parse the file_name to retrieve probing type.
            std::string file_name{itr->path().filename().string()};
            std::smatch ip_match;
            if (std::regex_search(file_name, ip_match, ipv4_regex)) {
                auto it = std::find(ips.begin(), ips.end(), ip_match[0]);
                if (it == ips.end()){
                    ips.emplace_back(ip_match[0]);
                }

            }
        }
        return ips;
    }

    std::vector<icmp_trigger_probes_t> extract_icmp_trigger_probes_from_file(const std::string & file_name, const Tins::IPv4Address & source){
        std::vector<icmp_trigger_probes_t> alias_test;

        std::ifstream infile(file_name);
        // Each line correspond to a ttl_exceeded probe, so parse and build it
        std::string line;
        while (std::getline(infile, line))
        {
            std::vector<std::string> tokens;
            split(line, tokens, ' ');
            auto target_ip = tokens[0];
            auto probe_ip = tokens[1];
            auto ttl = static_cast<uint8_t>(std::atoi(tokens[2].c_str()));
            auto flow_id = static_cast<uint16_t>(std::atoi(tokens[3].c_str())) + 24000;



            // Build the different probes
            auto ttl_exceeded_probe = build_icmp_triggering_probe(probe_ip, source, flow_id, 33435, ttl, Tins::ICMP::TIME_EXCEEDED);
            auto dst_unreachable_probe = build_icmp_triggering_probe(target_ip, source,  24000, 33435, 0, Tins::ICMP::DEST_UNREACHABLE);
            auto echo_reply_probe = build_icmp_triggering_probe(target_ip, source, 0, 0, 0, Tins::ICMP::Flags::ECHO_REPLY);

            alias_test.push_back(icmp_trigger_probes_t{ttl_exceeded_probe, dst_unreachable_probe, echo_reply_probe});
        }
        return alias_test;
    }
}

#endif //ICMPRATELIMITING_FILE_UTILS_T_HPP
