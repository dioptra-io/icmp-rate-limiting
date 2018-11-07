//
// Created by System Administrator on 06/11/2018.
//

#include "../include/rate_limit_individual_t.hpp"
#include <rate_limit_test_t.hpp>
#include <utils/file_utils_t.hpp>


using namespace Tins;
using namespace utils;

void rate_limit_individual_t::execute_individual_probes4(
        const NetworkInterface & sniff_interface,
        const probe_infos_t &probe_infos,
        int probing_rate,
        const std::string & output_dir_individual){
    // Probing rate represents the number of packets to send in 1 sec
    auto nb_probes = 5 * probing_rate;

    rate_limit_test_t<IPv4Address> rate_limit_test(nb_probes, probing_rate, sniff_interface,
                                                   std::vector<probe_infos_t>(1, probe_infos));

    auto icmp_type = probe_infos.icmp_type_str();

    auto real_target = probe_infos.get_real_target4();
    auto pcap_file_name = build_pcap_name(output_dir_individual, icmp_type, real_target.to_string(), "INDIVIDUAL", probing_rate);
    rate_limit_test.set_pcap_file(pcap_file_name);

    std::cout << "Starting " << icmp_type <<  " for " << real_target.to_string() << " with probing rate " << probing_rate <<  "...\n";
    rate_limit_test.start();

}

void rate_limit_individual_t::execute_individual_probes4(
        const std::vector<probe_infos_t> &probes_infos,
        const std::vector<int> & probing_rates,
        const std::string &output_dir_individual){
    auto sniff_interface = NetworkInterface::default_interface();

    /**
 *  Probe each interface separately with progressive rates.
 */
    std::cout << "Proceeding to the individual probing phase...\n";

    // Progressively increase the sending rate (log scale)
    for (const auto & probe_infos : probes_infos){
        for(const auto & probing_rate : probing_rates){

            execute_individual_probes4(sniff_interface, probe_infos, probing_rate, output_dir_individual);
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
}


std::stringstream rate_limit_individual_t::analyse_individual_probes4(
        const probe_infos_t &probe_infos,
        int probing_rate,
        const std::string & pcap_file){


    std::stringstream ostream;


    std::unordered_map<IPv4Address, IP> matchers;
    matchers.insert(std::make_pair(probe_infos.get_real_target4(), probe_infos.get_packet4()));
    rate_limit_analyzer_t rate_limit_analyzer(probe_infos.get_probing_style(), matchers) ;


    auto real_target = probe_infos.get_real_target4();

    // Start the analysis of responsiveness.
    rate_limit_analyzer.start(pcap_file);

    // Extract loss rate.
    auto loss_rate = rate_limit_analyzer.compute_loss_rate(probe_infos.get_real_target4());
    std::cout << "Loss rate: " << loss_rate << "\n";
    // Now extract relevant infos.
    auto triggering_rates_per_ip = rate_limit_analyzer.compute_icmp_triggering_rate4();
    auto transition_matrix_per_ip = rate_limit_analyzer.compute_loss_model4(real_target);
    if (triggering_rates_per_ip.at(real_target) != std::make_pair(-1, -1)) {
        auto change_behaviour_rate = triggering_rates_per_ip[real_target].first;

        auto line_ostream = build_output_line(
                probe_infos.get_real_target4(),
                "INDIVIDUAL",
                probing_rate,
                change_behaviour_rate,
                loss_rate,
                transition_matrix_per_ip.transition(0,0), transition_matrix_per_ip.transition(0,1), transition_matrix_per_ip.transition(1,0), transition_matrix_per_ip.transition(1,1),
                std::unordered_map<IPv4Address, double>());
        ostream << line_ostream.str();
    }
    return ostream;
}

std::stringstream rate_limit_individual_t::analyse_individual_probes4(const std::vector <probe_infos_t> & probes_infos,
                                             const std::vector <int> & probing_rates,
                                             const std::string & output_dir_individual
){

    std::stringstream ostream;

    for (const auto & probe_infos : probes_infos){
        for (const auto probing_rate: probing_rates){
            auto real_target = probe_infos.get_real_target4();
            auto icmp_type = probe_infos.icmp_type_str();
            auto pcap_file = build_pcap_name(output_dir_individual, icmp_type, real_target.to_string(), "INDIVIDUAL", probing_rate);
            try {
                ostream << analyse_individual_probes4(probe_infos, probing_rate, pcap_file).str();
            } catch (const pcap_error & error) {
                std::cerr << error.what() << "\n";
            }

        }

    }
    return ostream;
}


void rate_limit_individual_t::execute_individual_probes6(
        const NetworkInterface & sniff_interface,
        const probe_infos_t &probe_infos,
        int probing_rate,
        const std::string & output_dir_individual){
    // Probing rate represents the number of packets to send in 1 sec
    auto nb_probes = 5 * probing_rate;

    rate_limit_test_t<IPv6Address> rate_limit_test(nb_probes, probing_rate, sniff_interface,
                                                   std::vector<probe_infos_t>(1, probe_infos));

    auto icmp_type = probe_infos.icmp_type_str();

    auto real_target = probe_infos.get_real_target6();
    auto pcap_file_name = build_pcap_name(output_dir_individual, icmp_type, real_target.to_string(), "INDIVIDUAL", probing_rate);
    rate_limit_test.set_pcap_file(pcap_file_name);

    std::cout << "Starting " << icmp_type <<  " for " << real_target.to_string() << " with probing rate " << probing_rate <<  "...\n";
    rate_limit_test.start();

}

void rate_limit_individual_t::execute_individual_probes6(
        const std::vector<probe_infos_t> &probes_infos,
        const std::vector<int> & probing_rates,
        const std::string &output_dir_individual){
    auto sniff_interface = NetworkInterface::default_interface();

    /**
 *  Probe each interface separately with progressive rates.
 */
    std::cout << "Proceeding to the individual probing phase...\n";

    // Progressively increase the sending rate (log scale)
    for (const auto & probe_infos : probes_infos){
        for(const auto & probing_rate : probing_rates){

            execute_individual_probes6(sniff_interface, probe_infos, probing_rate, output_dir_individual);
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
}


std::stringstream rate_limit_individual_t::analyse_individual_probes6(
        const probe_infos_t &probe_infos,
        int probing_rate,
        const std::string & pcap_file){


    std::stringstream ostream;


    std::unordered_map<IPv6Address, IPv6> matchers;
    matchers.insert(std::make_pair(probe_infos.get_real_target6(), probe_infos.get_packet6()));
    rate_limit_analyzer_t rate_limit_analyzer(probe_infos.get_probing_style(), matchers) ;


    auto real_target = probe_infos.get_real_target6();

    // Start the analysis of responsiveness.
    rate_limit_analyzer.start(pcap_file);

    // Extract loss rate.
    auto loss_rate = rate_limit_analyzer.compute_loss_rate(probe_infos.get_real_target6());
    std::cout << "Loss rate: " << loss_rate << "\n";
    // Now extract relevant infos.
    auto triggering_rates_per_ip = rate_limit_analyzer.compute_icmp_triggering_rate6();
    auto transition_matrix_per_ip = rate_limit_analyzer.compute_loss_model6(real_target);
    if (triggering_rates_per_ip.at(real_target) != std::make_pair(-1, -1)) {
        auto change_behaviour_rate = triggering_rates_per_ip[real_target].first;

        auto line_ostream = build_output_line(
                probe_infos.get_real_target6(),
                "INDIVIDUAL",
                probing_rate,
                change_behaviour_rate,
                loss_rate,
                transition_matrix_per_ip.transition(0,0), transition_matrix_per_ip.transition(0,1), transition_matrix_per_ip.transition(1,0), transition_matrix_per_ip.transition(1,1),
                std::unordered_map<IPv6Address, double>());
        ostream << line_ostream.str();
    }
    return ostream;
}

std::stringstream rate_limit_individual_t::analyse_individual_probes6(const std::vector <probe_infos_t> & probes_infos,
                                                                      const std::vector <int> & probing_rates,
                                                                      const std::string & output_dir_individual
){

    std::stringstream ostream;

    for (const auto & probe_infos : probes_infos){
        for (const auto probing_rate: probing_rates){
            auto real_target = probe_infos.get_real_target6();
            auto icmp_type = probe_infos.icmp_type_str();
            auto pcap_file = build_pcap_name(output_dir_individual, icmp_type, real_target.to_string(), "INDIVIDUAL", probing_rate);
            try {
                ostream << analyse_individual_probes6(probe_infos, probing_rate, pcap_file).str();
            } catch (const pcap_error & error) {
                std::cerr << error.what() << "\n";
            }
        }

    }
    return ostream;
}