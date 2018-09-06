//
// Created by System Administrator on 29/08/2018.
//

#ifndef ICMPRATELIMITING_PROBE_INFOS_T_HPP
#define ICMPRATELIMITING_PROBE_INFOS_T_HPP

#include <tins/tins.h>
#include <utils/struct_utils_t.hpp>


class probe_infos_t {
public:
    explicit probe_infos_t(int group_id, int probing_rate, const Tins::IP &, const Tins::IPv4Address &, Tins::PDU::PDUType, utils::probing_style_t, utils::interface_type_t);

    const Tins::IP &get_packet() const;
    const Tins::IPv4Address &get_real_target() const;
    Tins::PDU::PDUType get_protocol() const;
    utils::probing_style_t get_probing_style() const;

    int get_group_id() const;

    utils::interface_type_t get_interface_type() const;

    std::string icmp_type_str() const;

    int get_probing_rate() const;

    void set_probing_rate(int m_probing_rate);

private:


    int m_group_id;
    int m_probing_rate;
    Tins::IP m_packet;
    Tins::IPv4Address m_real_target;
    Tins::PDU::PDUType m_protocol;
    utils::probing_style_t m_probing_style;
    utils::interface_type_t m_interface_type;


};

std::string to_file_name (const std::vector<probe_infos_t> & alias_test, char separator);


#endif //ICMPRATELIMITING_PROBE_INFOS_T_HPP
