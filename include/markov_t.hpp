//
// Created by System Administrator on 11/07/2018.
//

#ifndef ICMPRATELIMITING_GILBERT_ELLIOT_T_HPP
#define ICMPRATELIMITING_GILBERT_ELLIOT_T_HPP

#include <vector>
#include <iostream>
#include <numeric>

template <typename State, size_t n_state>
class markov_t {
public:
    using transition_matrix_t = std::vector<std::vector<double>>;

    markov_t() :
            states(n_state),
            transition_matrix(n_state, std::vector<double>(n_state))
    {
        states.resize(n_state);
        transition_matrix.resize(n_state);
        for (int i = 0; i < transition_matrix.size(); ++i){
            transition_matrix[i].resize(n_state);
        }
    }

    double transition(int from, int to) const {
        return transition_matrix[from][to];
    }

    void transition(int from, int to, double new_value){
        transition_matrix[from][to] = new_value;
    }

    bool is_correct(){
        for (int i = 0; i < transition_matrix.size(); ++i){
            auto sum_state = std::accumulate(transition_matrix[i].begin(), transition_matrix[i].end(), 0);
            if (sum_state != 1){
                return false;
            }
        }
        return true;
    }

private:
    std::vector<State> states;

    transition_matrix_t transition_matrix;
};


#endif //ICMPRATELIMITING_GILBERT_ELLIOT_T_HPP
