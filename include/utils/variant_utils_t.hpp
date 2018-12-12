//
// Created by System Administrator on 12/12/2018.
//

#ifndef ICMPRATELIMITING_VARIANT_UTILS_T_HPP
#define ICMPRATELIMITING_VARIANT_UTILS_T_HPP

#include <boost/variant.hpp>
#include <tins/tins.h>

template<typename F>
class visitor_t
        : public boost::static_visitor<>
{
public:
    using result_type = typename F::return_type;
    visitor_t(F f_p): f(f_p){}

    template<typename variant_type>
    result_type operator()(const variant_type & v_t) const
    {
        return f(v_t);
    }

private:
    F f;
};

class to_string_functor_t{
public:

    using return_type = std::string;

    template<typename T>
    std::string operator()(const T & t) const {
        return t.to_string();
    }
};

#endif //ICMPRATELIMITING_VARIANT_UTILS_T_HPP
