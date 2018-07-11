//
// Created by System Administrator on 10/07/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_ESTIMATE_HPP
#define ICMPRATELIMITING_RATE_LIMIT_ESTIMATE_HPP

#include <tins/tins.h>

struct rate_limit_estimate_t {
    Tins::IPv4Address ip;
    double bucket_total_size;
    double tokens_per_interval;
    double interval;
};


#endif //ICMPRATELIMITING_RATE_LIMIT_ESTIMATE_HPP
