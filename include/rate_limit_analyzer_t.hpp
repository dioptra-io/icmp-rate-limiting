//
// Created by System Administrator on 05/07/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_ANALYZER_HPP
#define ICMPRATELIMITING_RATE_LIMIT_ANALYZER_HPP

#include <tuple>
#include <unordered_map>
#include <tins/tins.h>
#include "rate_limit_estimate_t.hpp"
#include "markov_t.hpp"

class rate_limit_analyzer_t {

public:

    enum class probing_style_t{
        DIRECT, INDIRECT
    };

    using intervals_t = std::tuple<bool, double, double>;

    rate_limit_analyzer_t(probing_style_t);

    using port_ttl_ip_t = std::tuple<uint16_t, uint8_t, Tins::IPv4Address>;
    using responsive_info_probe_t = std::pair<bool, Tins::Packet>;
    using responsiveness_t = std::unordered_map<Tins::IPv4Address, std::vector<responsive_info_probe_t>>;

    void start(const std::string &pcap_file);

    using time_interval_t = std::pair<double,double>;
    using responsiveness_time_interval_t = std::tuple<bool, int, time_interval_t >;
    using time_series_t = std::vector<responsiveness_time_interval_t>;

    std::unordered_map<Tins::IPv4Address, time_series_t> extract_responsiveness_time_series();

    std::unordered_map<Tins::IPv4Address, double> compute_loss_rate();


    using gilbert_elliot_t = markov_t<int, 2>;
    gilbert_elliot_t compute_loss_model(const std::vector<responsive_info_probe_t> & );


    void dump_loss_rate();
    void dump_time_series();
    void dump_gilbert_eliot();

    probing_style_t get_probing_style() const;


private:
    // To match unresponsive probes with their original ip.
    bool match_probe(const Tins::IP &match, const Tins::IP &probe);

    // Private functions to compute statistics indicators.
    double compute_loss_rate(const std::vector<responsive_info_probe_t> &);
    time_series_t extract_responsiveness_time_series(const std::vector <responsive_info_probe_t> &);

    rate_limit_estimate_t compute_mean_stddev(const time_series_t & );

    void dump_transition_matrix(const gilbert_elliot_t &);

    void sort_by_timestamp(std::vector<Tins::Packet> &packets);
//    std::vector<intervals_t> compute_responsiveness();
    // Analysis
    probing_style_t probing_style;
    std::unordered_map<Tins::IPv4Address, Tins::IP> matchers;

    responsiveness_t packets_per_interface;
    std::vector<Tins::Packet> outgoing_packets;
    std::vector<Tins::Packet> icmp_replies;


};


#endif //ICMPRATELIMITING_RATE_LIMIT_ANALYZER_HPP
