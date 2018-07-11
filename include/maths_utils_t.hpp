//
// Created by System Administrator on 10/07/2018.
//

#ifndef ICMPRATELIMITING_MATHS_UTILS_T_HPP
#define ICMPRATELIMITING_MATHS_UTILS_T_HPP

#include <cmath>
#include <utility>
#include <algorithm>

template<typename Iterator>
std::pair<double, double> mean_stddev(Iterator begin, Iterator end)
{
    double sum = 0.0;
    double mean = 0.0;
    double standardDeviation = 0.0;
    auto n = std::distance(begin, end);

    for(auto it = begin; it != end; ++it) {
        sum += *it;
    }

    mean = sum/n;

    for(auto it = begin; it != end; ++it) {
        standardDeviation += pow(*it - mean, 2);
    }
    return std::make_pair(mean, sqrt(standardDeviation / n));
}


#endif //ICMPRATELIMITING_MATHS_UTILS_T_HPP
