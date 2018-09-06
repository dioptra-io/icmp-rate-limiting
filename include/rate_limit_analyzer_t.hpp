//
// Created by System Administrator on 05/07/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_ANALYZER_HPP
#define ICMPRATELIMITING_RATE_LIMIT_ANALYZER_HPP

#include <tuple>
#include <unordered_map>
#include <tins/tins.h>

#include <utils/struct_utils_t.hpp>
#include <rate_limit_estimate_t.hpp>
#include <markov_t.hpp>
#include <alias_t.hpp>

class rate_limit_analyzer_t {

public:

    using intervals_t = std::tuple<bool, double, double>;

    explicit rate_limit_analyzer_t(utils::probing_style_t);

    rate_limit_analyzer_t(utils::probing_style_t, const std::unordered_map<Tins::IPv4Address, Tins::IP> & );

    using port_ttl_ip_t = std::tuple<uint16_t, uint8_t, Tins::IPv4Address>;
    using responsiveness_t = std::unordered_map<Tins::IPv4Address, std::vector<utils::responsive_info_probe_t>>;

    void start(const std::string &pcap_file);

    using time_interval_t = std::pair<double,double>;
    using responsiveness_time_interval_t = std::tuple<bool, int, time_interval_t >;
    using time_series_t = std::vector<responsiveness_time_interval_t>;

    std::unordered_map<Tins::IPv4Address, time_series_t> extract_responsiveness_time_series();

    std::unordered_map<Tins::IPv4Address, double> compute_loss_rate();

    double compute_loss_rate(const Tins::IPv4Address & ip) const;

    gilbert_elliot_t compute_loss_model(const Tins::IPv4Address & address) const;

    std::unordered_map<Tins::IPv4Address, utils::packet_interval_t> compute_icmp_triggering_rate() const;



    void dump_loss_rate();
    void dump_time_series();
    void dump_gilbert_eliot();

    utils::probing_style_t get_probing_style() const;
    std::vector<utils::responsive_info_probe_t> get_raw_packets(const Tins::IPv4Address & ) const;
    time_series_t get_responsiveness(const Tins::IPv4Address &);

private:
    // To match unresponsive probes with their original ip.
    bool match_probe(const Tins::IP &match, const Tins::IP &probe);

    // Private functions to compute statistics indicators.
    double compute_loss_rate(const std::vector<utils::responsive_info_probe_t> &) const;
    gilbert_elliot_t compute_loss_model(const std::vector<utils::responsive_info_probe_t> & ) const;
    time_series_t extract_responsiveness_time_series(const std::vector <utils::responsive_info_probe_t> &);

    rate_limit_estimate_t compute_mean_stddev(const time_series_t & );

    void dump_transition_matrix(const gilbert_elliot_t &);

    void sort_by_timestamp(std::vector<Tins::Packet> &packets);

    utils::packet_interval_t compute_icmp_triggering_rate(const std::vector<utils::responsive_info_probe_t> &) const;


//    std::vector<intervals_t> compute_responsiveness();
    // Analysis
    utils::probing_style_t probing_style;
    std::unordered_map<Tins::IPv4Address, Tins::IP> matchers;

    responsiveness_t packets_per_interface;
    std::vector<Tins::Packet> outgoing_packets;
    std::vector<Tins::Packet> icmp_replies;


};


#endif //ICMPRATELIMITING_RATE_LIMIT_ANALYZER_HPP
