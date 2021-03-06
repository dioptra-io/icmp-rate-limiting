//
// Created by System Administrator on 18/07/2018.
//

#ifndef ICMPRATELIMITING_STRUCT_UTILS_HPP
#define ICMPRATELIMITING_STRUCT_UTILS_HPP

#include <tins/tins.h>
#include "alias_t.hpp"

namespace utils{
    struct stats_t{
        Tins::IPv4Address ip;
        int triggering_probing_rate;
        double loss_rate;
        gilbert_elliot_t burst_model;

    };

    struct options_t{
        bool analyse_only = false;
        bool probe_only = false;
        bool group_only = false;
        bool individual_only = false;
        bool is_custom_probing_rates = false;
        std::vector<int> custom_probing_rates;
        bool use_individual_for_analyse = false;
        bool use_group_for_analyse = false;
        bool first_only = false;
        std::string pcap_dir_individual = "";
        std::string pcap_dir_groups = "";
        int measurement_time = 5;
        int low_rate_dpr = 10;
        std::string individual_result_file = "";
        int starting_probing_rate = 128;
        double exponential_reason = 1.05;

    };

    enum class probing_style_t {DIRECT, INDIRECT, UNKNOWN};
    enum class interface_type_t {CANDIDATE = 0, WITNESS = 1, UNKNOWN = 2};
    using packet_interval_t = std::pair<int, int>;
    using responsive_info_probe_t = std::pair<bool, Tins::Packet>;

}

#endif //ICMPRATELIMITING_STRUCT_UTILS_HPP
