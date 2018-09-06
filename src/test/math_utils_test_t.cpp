//
// Created by System Administrator on 01/08/2018.
//

#include <vector>
#include <iostream>
#include "../../include/utils/maths_utils_t.hpp"

using namespace utils;
namespace{
    double three_digits(double decimal){
        auto a = static_cast<int>(round(decimal * 1000.0));
        return a / 1000.0;
    }
}

int main(){

    std::vector<double> v1 {65.21, 64.75, 65.26, 65.76, 65.96};
    std::vector<double> v2 {67.25, 66.39, 66.12, 65.70, 66.64};

    auto m_var_v1 = mean_stddev(v1.begin(), v1.end());

    assert(three_digits(m_var_v1.first) == 65.388);
    assert(three_digits(m_var_v1.second) == 0.184);

    auto m_var_v2 = mean_stddev(v2.begin(), v2.end());
    assert(three_digits(m_var_v2.first) == 66.42);
    assert(three_digits(m_var_v2.second) == 0.269);


    assert(three_digits(cov_correlation(v1, v2).first) == -0.046);

    std::cout << "All tests passed\n";

}