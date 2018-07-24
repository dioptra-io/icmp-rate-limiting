//
// Created by System Administrator on 24/07/2018.
//

#ifndef ICMPRATELIMITING_FILE_UTILS_T_HPP
#define ICMPRATELIMITING_FILE_UTILS_T_HPP
#include <string>
#include <regex>
#include <boost/filesystem.hpp>
#include <vector>

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
}

#endif //ICMPRATELIMITING_FILE_UTILS_T_HPP
