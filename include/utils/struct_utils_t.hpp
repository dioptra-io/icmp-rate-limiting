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

    enum class probing_style_t {DIRECT, INDIRECT, UNKNOWN};
    enum class interface_type_t {CANDIDATE, WITNESS, UNKNOWN};
    using packet_interval_t = std::pair<int, int>;
    using responsive_info_probe_t = std::pair<bool, Tins::Packet>;

}

#endif //ICMPRATELIMITING_STRUCT_UTILS_HPP
