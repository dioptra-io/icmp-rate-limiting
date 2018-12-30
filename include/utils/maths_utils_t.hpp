//
// Created by System Administrator on 10/07/2018.
//

#ifndef ICMPRATELIMITING_MATHS_UTILS_T_HPP
#define ICMPRATELIMITING_MATHS_UTILS_T_HPP

#include <cmath>
#include <utility>
#include <algorithm>

namespace utils{


    template<typename Integer>
    Integer gcd(Integer u, Integer v){
        while ( v != 0) {
            Integer r = u % v;
            u = v;
            v = r;
        }
        return u;
    }
    template<typename Integer>
    Integer lcm(Integer u, Integer v){
        return std::abs(u * v) / gcd(u, v);
    }

    template<typename Integer>
    Integer lcm(const std::vector<Integer> & v){
        auto lcm_v = v[0];
        for (int i = 1; i < v.size(); ++i){
            lcm_v = lcm(lcm_v, v[i]);
        }
        return lcm_v;
    }

    template<typename Integer>
    Integer gcd(const std::vector<Integer> & v){
        auto gcd_v = v[0];
        for (int i = 1; i < v.size(); ++i){
            gcd_v = gcd(gcd_v, v[i]);
        }
        return gcd_v;
    }


    template<typename Real>
    double significant_digits(Real decimal, int digit_number){
        auto digits = pow(10, digit_number);
        auto a = static_cast<int>(round(decimal * static_cast<int>(digits)));
        return a / digits;
    }


    template<typename Iterator>
    std::pair<double, double> mean_stddev(Iterator begin, Iterator end)
    {
        double sum = 0.0;
        double mean = 0.0;
        double variance = 0.0;
        auto n = std::distance(begin, end);

        for(auto it = begin; it != end; ++it) {
            sum += *it;
        }

        mean = sum/n;

        for(auto it = begin; it != end; ++it) {
            variance += pow(*it - mean, 2);
        }

        variance /= n;
        return std::make_pair(mean, variance);
    }


    /**
     * cov : E((X-E(X))(Y-E(Y)))
     * correlation : cov(X,Y)/(var(X)var(Y))
     * @tparam Iterator
     * @param begin1
     * @param end1
     * @param begin2
     * @param end2
     * @return
     */
    template<typename Real>
    std::pair<double, double> cov_correlation(const std::vector<Real> & X, const std::vector<Real> & Y){

        auto max_size = std::min(X.size(), Y.size());

        // First part of the product
        auto e_x_var_x = mean_stddev(X.begin(), X.end());
        auto e_x = e_x_var_x.first;
        std::vector<double> X_e_X;
        std::transform(X.begin(), X.end(), std::back_inserter(X_e_X), [e_x](const auto & x){
            return x - e_x;
        });

        // Second part of the product
        auto e_y_var_y = mean_stddev(Y.begin(), Y.end());
        auto e_y = e_y_var_y.first;
        std::vector<double> Y_e_Y;
        std::transform(Y.begin(), Y.end(), std::back_inserter(Y_e_Y), [e_y](const auto & y){
            return y - e_y;
        });


        // Product
        std::vector<double> product_X_e_X_Y_e_Y (X_e_X);
        for (int i = 0; i < max_size; ++i){
            product_X_e_X_Y_e_Y[i] *= Y_e_Y[i];
        }
        // Readjust in case of inequal number of data.
        product_X_e_X_Y_e_Y.resize(max_size);


        auto var_x = e_x_var_x.second;
        auto var_y = e_y_var_y.second;

        auto cov = mean_stddev(product_X_e_X_Y_e_Y.begin(), product_X_e_X_Y_e_Y.end()).first;


        auto cor = 0.0;

        if(var_x != 0 && var_y != 0){
            cor = cov / (sqrt(var_x) * sqrt(var_y));
        }

        return std::make_pair(cov, cor);
    }


}



#endif //ICMPRATELIMITING_MATHS_UTILS_T_HPP
