//
// Created by System Administrator on 10/07/2018.
//

#ifndef ICMPRATELIMITING_CONTAINER_UTILS_T_HPP
#define ICMPRATELIMITING_CONTAINER_UTILS_T_HPP

#include <vector>

template<typename Map>
std::vector<typename Map::mapped_type> values(const Map & map){
    std::vector<typename Map::mapped_type> result;
    std::transform(map.begin(), map.end(), std::back_inserter(result), [](const auto & pair){
        return pair.second;
    });
    return result;
}


#endif //ICMPRATELIMITING_CONTAINER_UTILS_T_HPP
