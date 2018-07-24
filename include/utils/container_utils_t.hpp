//
// Created by System Administrator on 10/07/2018.
//

#ifndef ICMPRATELIMITING_CONTAINER_UTILS_T_HPP
#define ICMPRATELIMITING_CONTAINER_UTILS_T_HPP

#include <vector>
#include <sstream>
#include <utility>
#include <algorithm>

namespace utils{
    template<typename Map>
    std::vector<typename Map::mapped_type> values(const Map & map){
        std::vector<typename Map::mapped_type> result;
        std::transform(map.begin(), map.end(), std::back_inserter(result), [](const auto & pair){
            return pair.second;
        });
        return result;
    }

    template< typename T, typename Pred >
    typename std::vector<T>::iterator
    insert_sorted(std::vector<T> & vec, const T & item, Pred pred )
    {
        return vec.insert(std::upper_bound( vec.cbegin(), vec.cend(), item, pred ), item );

    }

    template<typename Map>
    std::vector<std::pair<std::remove_const_t<typename Map::key_type>, typename Map::mapped_type>> to_sorted_vector(const Map & map){
        std::vector<std::pair<std::remove_const_t<typename Map::key_type>, typename Map::mapped_type>> sorted_vector;

        for (const auto & p: map) {
            std::pair<std::remove_const_t<typename Map::key_type>, typename Map::mapped_type> copy (p);
            insert_sorted(sorted_vector, std::move(copy), [](const auto & p1, const auto & p2){
                return p1.first < p2.first;
            });
        }

//    std::sort(sorted_vector.begin(), sorted_vector.end(), [](const auto & p1, const auto & p2){
//        return p1.first < p2.first;
//    });

        return sorted_vector;
    }

    template<typename Map>
    std::vector<typename Map::mapped_type> values_sorted_by_keys(const Map & map){
        auto pair_results = to_sorted_vector(map);

        std::vector<typename decltype(pair_results)::value_type::second_type> results;

        std::transform(pair_results.begin(), pair_results.end(), std::back_inserter(results), [](const auto & pair){
            return pair.second;
        });

        return results;
    }


    template <typename Map>
    Map extend(const Map & map1, const Map & map2){
        Map result;
        std::copy(map1.begin(), map1.end(), std::inserter(result, result.end()));
        std::copy(map2.begin(), map2.end(), std::inserter(result, result.end()));
        return result;
    }



    template <class Container>
    void split(const std::string& str, Container& cont, char delim = ' ')
    {
        std::stringstream ss(str);
        std::string token;
        while (std::getline(ss, token, delim)) {
            cont.push_back(token);
        }
    }
}


#endif //ICMPRATELIMITING_CONTAINER_UTILS_T_HPP
