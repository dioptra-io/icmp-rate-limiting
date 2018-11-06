//
// Created by System Administrator on 06/11/2018.
//

#ifndef ICMPRATELIMITING_SERIES_T_HPP
#define ICMPRATELIMITING_SERIES_T_HPP

#include <string>
#include <markov_t.hpp>
#include "alias_t.hpp"

class series_t {



private:
    double loss_rate;
    double change_behaviour_time;
    gilbert_elliot_t transition_matrix;


};


#endif //ICMPRATELIMITING_SERIES_T_HPP
