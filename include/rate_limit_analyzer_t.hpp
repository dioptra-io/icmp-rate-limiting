//
// Created by System Administrator on 05/07/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_ANALYZER_HPP
#define ICMPRATELIMITING_RATE_LIMIT_ANALYZER_HPP

#include <tuple>
#include <unordered_map>
#include <tins/tins.h>

#include <utils/struct_utils_t.hpp>
#include <utils/maths_utils_t.hpp>
#include <rate_limit_estimate_t.hpp>
#include <markov_t.hpp>
#include <alias_t.hpp>

class rate_limit_analyzer_t {

public:

    using intervals_t = std::tuple<bool, double, double>;

    /**
     * Constructors
     */

    explicit rate_limit_analyzer_t(utils::probing_style_t probing_style, Tins::PDU::PDUType);
    rate_limit_analyzer_t(utils::probing_style_t probing_style, const std::unordered_map<Tins::IPv4Address, Tins::IP> & matchers);
    rate_limit_analyzer_t(utils::probing_style_t probing_style, const std::unordered_map<Tins::IPv6Address, Tins::IPv6> & matchers);


    /**
     * Aliases
     */

    template<typename IPvAddress>
    using responsiveness_t = std::unordered_map<IPvAddress, std::vector<utils::responsive_info_probe_t>>;

    using time_interval_t = std::pair<double,double>;
    using responsiveness_time_interval_t = std::tuple<bool, int, time_interval_t >;
    using time_series_t = std::vector<responsiveness_time_interval_t>;

    void start(const std::string &pcap_file);

    std::unordered_map<Tins::IPv4Address, time_series_t> extract_responsiveness_time_series4();
    std::unordered_map<Tins::IPv6Address, time_series_t> extract_responsiveness_time_series6();
    
    std::unordered_map<Tins::IPv4Address, double> compute_loss_rate4();
    double compute_loss_rate(const Tins::IPv4Address & ip) const;

    std::unordered_map<Tins::IPv6Address, double> compute_loss_rate6();
    double compute_loss_rate(const Tins::IPv6Address & ip) const;

    gilbert_elliot_t compute_loss_model4(const Tins::IPv4Address & address) const;
    gilbert_elliot_t compute_loss_model6(const Tins::IPv6Address & address) const;


    std::unordered_map<Tins::IPv4Address, utils::packet_interval_t> compute_icmp_triggering_rate4() const;

    std::unordered_map<Tins::IPv6Address, utils::packet_interval_t> compute_icmp_triggering_rate6() const;


    void dump_loss_rate();
    void dump_time_series();


    std::string serialize_raw4();
    std::string serialize_raw6();
    
    std::string serialize_raw4(const Tins::IPv4Address &);
    std::string serialize_raw6(const Tins::IPv4Address &);


    utils::probing_style_t get_probing_style() const;
    std::vector<utils::responsive_info_probe_t> get_raw_packets4(const Tins::IPv4Address &ip) const;
    std::vector<utils::responsive_info_probe_t> get_raw_packets6(const Tins::IPv6Address &ip) const;

    time_series_t get_responsiveness(const Tins::IPv4Address & address);

private:
    // To match unresponsive probes with their original ip.
    bool match_probe(const Tins::IP &match, const Tins::IP &probe);

    // Private functions to compute statistics indicators.
    double compute_loss_rate(const std::vector<utils::responsive_info_probe_t> & responsive_info_probes) const;
    gilbert_elliot_t compute_loss_model(const std::vector<utils::responsive_info_probe_t> & responsive_info_probes) const;

    time_series_t extract_responsiveness_time_series(const std::vector <utils::responsive_info_probe_t> & packet_serie);
    rate_limit_estimate_t compute_mean_stddev(const time_series_t & responsiveness_time_interval );


    void dump_transition_matrix(const gilbert_elliot_t & loss_model);
    void sort_by_timestamp(std::vector<Tins::Packet> &packets);
    utils::packet_interval_t compute_icmp_triggering_rate(const std::vector<utils::responsive_info_probe_t> & data) const;


//    std::vector<intervals_t> compute_responsiveness();
    // Analysis

    Tins::PDU::PDUType ip_family;
    utils::probing_style_t probing_style;
    std::unordered_map<Tins::IPv4Address, Tins::IP> matchers4;
    std::unordered_map<Tins::IPv6Address, Tins::IPv6> matchers6;


    responsiveness_t<Tins::IPv4Address> packets_per_interface4;
    responsiveness_t<Tins::IPv6Address> packets_per_interface6;
    std::vector<Tins::Packet> outgoing_packets;
    std::vector<Tins::Packet> icmp_replies;


};


#endif //ICMPRATELIMITING_RATE_LIMIT_ANALYZER_HPP
