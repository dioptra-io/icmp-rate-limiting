//
// Created by System Administrator on 10/07/2018.
//

#ifndef ICMPRATELIMITING_TINS_UTILS_T_HPP
#define ICMPRATELIMITING_TINS_UTILS_T_HPP
#include <tins/tins.h>
#include <unordered_map>
#include <probe_infos_t.hpp>

namespace utils {
    template<typename T>
    class HandlerProxy {
    public:
        typedef T *ptr_type;

        typedef bool (T::*fun_type)(Tins::Packet &);

        HandlerProxy(ptr_type ptr, fun_type function)
                : object_(ptr), fun_(function) {}

        bool operator()(Tins::Packet &pdu) {
            return (object_->*fun_)(pdu);
        }

    private:
        ptr_type object_;
        fun_type fun_;
    };

    template<typename T>
    HandlerProxy<T> make_sniffer_handler(T *ptr,
                                         typename HandlerProxy<T>::fun_type function) {
        return HandlerProxy<T>(ptr, function);
    }

    std::unordered_map<Tins::IPv4Address, Tins::IP> retrieve_matchers(const Tins::IPv4Address & test_ip, const std::string & absolute_path);
}

#endif //ICMPRATELIMITING_TINS_UTILS_T_HPP
