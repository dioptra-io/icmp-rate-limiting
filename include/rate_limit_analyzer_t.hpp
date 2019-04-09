//
// Created by System Administrator on 05/07/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_ANALYZER_HPP
#define ICMPRATELIMITING_RATE_LIMIT_ANALYZER_HPP

#include <tuple>
#include <unordered_map>
#include <tins/tins.h>

#include <utils/container_utils_t.hpp>
#include <utils/struct_utils_t.hpp>
#include <utils/maths_utils_t.hpp>
#include <rate_limit_estimate_t.hpp>
#include <markov_t.hpp>
#include <alias_t.hpp>
#include "probe_infos_t.hpp"

class rate_limit_analyzer_t {

public:

    using intervals_t = std::tuple<bool, double, double>;

    enum class change_point_type_t{
        MEAN, VAR
    };
    /**
     * Constructors
     */
    rate_limit_analyzer_t();
    explicit rate_limit_analyzer_t(utils::probing_style_t probing_style, Tins::PDU::PDUType);

    rate_limit_analyzer_t(utils::probing_style_t probing_style, const std::unordered_map<Tins::IPv4Address, Tins::IP> & matchers);

    rate_limit_analyzer_t(utils::probing_style_t probing_style, const std::unordered_map<Tins::IPv6Address, Tins::IPv6> & matchers);

    rate_limit_analyzer_t(utils::probing_style_t probing_style,
                          const std::unordered_map<Tins::IPv4Address, Tins::IP> & matchers4,
                          const std::unordered_map<Tins::IPv6Address, Tins::IPv6> & matchers6);
    // Copy constructor
    rate_limit_analyzer_t (const rate_limit_analyzer_t & other);



    static rate_limit_analyzer_t build_rate_limit_analyzer_t_from_probe_infos(const std::vector<probe_infos_t> & probes_infos);
    /**
     * Aliases
     */

    template<typename T>
    using responsiveness_t = std::unordered_map<T, std::vector<utils::responsive_info_probe_t>>;

    using time_interval_t = std::pair<double,double>;
    using responsiveness_time_interval_t = std::tuple<bool, int, time_interval_t >;
    using time_series_t = std::vector<responsiveness_time_interval_t>;

    /**
     * Compute the responsiveness and put it in the packets_per_interface
     * @param pcap_file
     */
    void start(const std::string &pcap_file);

    std::unordered_map<std::string, time_series_t> extract_responsiveness_time_series();

    /**
     * Compute the loss rate
     * @return
     */
    std::unordered_map<std::string, double> compute_loss_rate();
    double compute_loss_rate(const std::string & ip) const;
    /**
     * Compute the transition matrices
     * @param address
     * @return
     */
    gilbert_elliot_t compute_loss_model(const std::string & address) const;

    /**
     * Compute the changing behaviour moment of a time serie
     * @return
     */
    std::unordered_map<std::string, int> compute_icmp_change_point() const;

    int compute_change_point(const std::string &) const;
    int compute_change_point(const std::vector<int> &data, change_point_type_t) const;

    std::pair<std::vector<int>, std::vector<int>> adjust_time_series_length(const std::string & ip_address1,
            const std::string & ip_address2);


    /**
     * Compute the correlation between two time series (they must have almost the same number of element)
     * @param ip_address1
     * @param ip_address2
     * @return
     */

    double correlation(const std::string & ip_address1,
                        const std::string &ip_address2);

    double correlation_high_low(const std::string & ip_address1,
                                const std::string &ip_address2);


    void dump_loss_rate();
    void dump_time_series();


    std::string serialize_raw();
    
    std::string serialize_raw(const std::string &);



    std::vector<int> responsiveness_to_binary(const std::vector<utils::responsive_info_probe_t> & responses) const ;

    utils::probing_style_t get_probing_style() const;
    std::vector<utils::responsive_info_probe_t> get_raw_packets(const std::string &ip) const;

    time_series_t get_responsiveness(const std::string & address);

private:
    // To match unresponsive probes with their original ip.
    bool match_probe(const Tins::IP &match, const Tins::IP &probe);

    // Private functions to compute statistics indicators.
    double compute_loss_rate(const std::vector<utils::responsive_info_probe_t> & responsive_info_probes) const;
    gilbert_elliot_t compute_loss_model(const std::vector<utils::responsive_info_probe_t> & responsive_info_probes) const;
    double correlation(const std::vector<utils::responsive_info_probe_t> &raw_router_1,
                       const std::vector<utils::responsive_info_probe_t> &raw_router_2);


    time_series_t extract_responsiveness_time_series(const std::vector <utils::responsive_info_probe_t> & packet_serie);
    rate_limit_estimate_t compute_mean_stddev(const time_series_t & responsiveness_time_interval );


    void dump_transition_matrix(const gilbert_elliot_t & loss_model);
    void sort_by_timestamp(std::vector<Tins::Packet> &packets);
    int compute_change_point(const std::vector<utils::responsive_info_probe_t> &data, change_point_type_t) const;

//    std::vector<intervals_t> compute_responsiveness();
    // Analysis

    Tins::PDU::PDUType ip_family;
    utils::probing_style_t probing_style;
    std::unordered_map<Tins::IPv4Address, Tins::IP> matchers4;
    std::unordered_map<Tins::IPv6Address, Tins::IPv6> matchers6;


    responsiveness_t<std::string> packets_per_interface;
    std::vector<Tins::Packet> outgoing_packets;
    std::vector<Tins::Packet> icmp_replies;
    std::unordered_map<std::pair<uint16_t, uint16_t>,std::vector<Tins::Packet>, utils::pairhash> match_icmp_replies;


};


#endif //ICMPRATELIMITING_RATE_LIMIT_ANALYZER_HPP
