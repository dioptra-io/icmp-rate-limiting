//
// Created by System Administrator on 06/11/2018.
//

#include "../include/rate_limit_individual_t.hpp"

#include <map>
#include <unordered_map>
#include <rate_limit_test_t.hpp>
#include <utils/file_utils_t.hpp>
#include <utils/network_utils_t.hpp>
#include <algorithm_context_t.hpp>


using namespace Tins;
using namespace utils;


void rate_limit_individual_t::execute_individual_probes4(
        const NetworkInterface & sniff_interface,
        const probe_infos_t &probe_infos,
        int probing_rate,
        const std::string & output_dir_individual){
    // Probing rate represents the number of packets to send in 1 sec
    auto nb_probes = measurement_time * probing_rate;

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
        const  std::vector<probe_infos_t> &probes_infos,
        int    starting_probing_rate,
        const std::pair<double, double> & target_loss_rate_interval,
        const options_t & options,
        algorithm_context_t & algorithm_context){
    auto sniff_interface = NetworkInterface::default_interface();

    /**
     *  Probe each interface until it reaches the target loss rate.
     *  It works as TCP slow start and then linear search.
     */
    std::cout << "Proceeding to the individual probing phase...\n";

    std::unordered_map<IPv4Address, int> triggering_rates;

//    // Sort probes_infos to put first the candidates.
//    std::stable_sort(probes_infos.begin(), probes_infos.end(), [](const auto & probe_infos1, const auto & probe_infos2){
//        return static_cast<int>(probe_infos1.get_interface_type()) < static_cast<int>(probe_infos2.get_interface_type());
//    });

    // Progressively adapt the sending rate so the targeted loss rate is obtained on first candidate.

    auto probe_infos = probes_infos[0];

    auto is_binary_search = false;
    auto probing_rate = starting_probing_rate;
    auto binary_search_iteration = 0;
    std::map<int, double> loss_rate_by_probing_rate;

    auto real_target = probe_infos.get_real_target4();

    while(binary_search_iteration < maximum_binary_search_iteration) {

        if (probing_rate >= maximum_probing_rate || probing_rate < minimum_probing_rate) {
            std::cout << "No triggering probing rate found for the target loss rate interval ["
                      << target_loss_rate_interval.first
                      << ", " << target_loss_rate_interval.second << "] for " << real_target << "\n";
            break;
        }

        execute_individual_probes4(sniff_interface, probe_infos, probing_rate, options.pcap_dir_individual);
        std::unordered_map<IPv4Address, IP> matchers;
        matchers.insert(std::make_pair(probe_infos.get_real_target4(), probe_infos.get_packet4()));

        rate_limit_analyzer_t rate_limit_analyzer{probe_infos.get_probing_style(), matchers};


        auto icmp_type = probe_infos.icmp_type_str();
        auto pcap_file = build_pcap_name(options.pcap_dir_individual, icmp_type, real_target.to_string(), "INDIVIDUAL",
                                         probing_rate);

        rate_limit_analyzer.start(pcap_file);
        algorithm_context.get_analyzed_pcap_file()[pcap_file] = std::make_unique<rate_limit_analyzer_t>(rate_limit_analyzer);

        auto loss_rate = rate_limit_analyzer.compute_loss_rate(real_target);
        bool continue_probing = compute_next_probing_rate(loss_rate,
                                  real_target,
                                  loss_rate_by_probing_rate,
                                  probing_rate,
                                  starting_probing_rate,
                                  triggering_rates,
                                  target_loss_rate_interval,
                                  is_binary_search,
                                  binary_search_iteration);

        if (!continue_probing){
            break;
        }

        std::this_thread::sleep_for(std::chrono::seconds(measurement_time + 1));
    }

    for (int i = 1; i < probes_infos.size(); ++i){
        std::this_thread::sleep_for(std::chrono::seconds(measurement_time + 1));
        execute_individual_probes4(sniff_interface, probes_infos[i], minimum_probing_rate, options.pcap_dir_individual);
    }

    for (int i = 1; i < probes_infos.size(); ++i){
        std::this_thread::sleep_for(std::chrono::seconds(measurement_time + 1));
        execute_individual_probes4(sniff_interface, probes_infos[i], triggering_rates[probe_infos.get_real_target4()], options.pcap_dir_individual);
    }


    auto result_triggering_rate = triggering_rates[real_target];
    algorithm_context.set_triggering_rate(result_triggering_rate);
    algorithm_context.set_triggering_rate_already_found(true);
}


std::stringstream rate_limit_individual_t::analyse_individual_probes4(
        const probe_infos_t &probe_infos,
        int probing_rate,
        const std::string & pcap_file,
        algorithm_context_t & algorithm_context
){


    std::stringstream ostream;


    std::unordered_map<IPv4Address, IP> matchers;
    matchers.insert(std::make_pair(probe_infos.get_real_target4(), probe_infos.get_packet4()));
    rate_limit_analyzer_t rate_limit_analyzer(probe_infos.get_probing_style(), matchers) ;

    auto it = algorithm_context.get_analyzed_pcap_file().find(pcap_file);
    if ( it != algorithm_context.get_analyzed_pcap_file().end()){
        rate_limit_analyzer = *(it->second);
    }
    else {
        // Start the analysis of responsiveness.
        rate_limit_analyzer.start(pcap_file);
        algorithm_context.get_analyzed_pcap_file()[pcap_file] = std::make_unique<rate_limit_analyzer_t>(rate_limit_analyzer);
    }
    auto real_target = probe_infos.get_real_target4();

    // Extract loss rate.
    auto loss_rate = rate_limit_analyzer.compute_loss_rate(probe_infos.get_real_target4());
    std::cout << "Loss rate: " << loss_rate << "\n";
    // Now extract relevant infos.
    auto change_point = rate_limit_analyzer.compute_icmp_change_point4(real_target);
    auto transition_matrix_per_ip = rate_limit_analyzer.compute_loss_model4(real_target);

    auto line_ostream = build_output_line(
            probe_infos.get_real_target4(),
            "INDIVIDUAL",
            probing_rate,
            change_point,
            loss_rate,
            transition_matrix_per_ip.transition(0,0), transition_matrix_per_ip.transition(0,1), transition_matrix_per_ip.transition(1,0), transition_matrix_per_ip.transition(1,1),
            std::unordered_map<IPv4Address, double>());
    ostream << line_ostream.str();
    return ostream;
}

void rate_limit_individual_t::analyse_individual_probes4(const std::vector <probe_infos_t> & probes_infos,
                                             const std::pair<double, double> & target_loss_rate_interval,
                                             const options_t & options,
                                             algorithm_context_t & algorithm_context
){


    std::unordered_map<IPv4Address, int> triggering_rates;

    // Sort probes_infos to put first the candidates.
//    std::stable_sort(probes_infos.begin(), probes_infos.end(), [](const auto & probe_infos1, const auto & probe_infos2){
//        return static_cast<int>(probe_infos1.get_interface_type()) < static_cast<int>(probe_infos2.get_interface_type());
//    });
    int triggering_rate = 0;
    if (algorithm_context.is_triggering_rate_already_found()){
        triggering_rate = algorithm_context.get_triggering_rate();
    }
    else {
        triggering_rate = find_triggering_rate(probes_infos[0], probes_infos, minimum_probing_rate, target_loss_rate_interval, options.pcap_dir_individual, "INDIVIDUAL", triggering_rates);
    }

    for (const auto & probe_infos: probes_infos){
        auto icmp_type = probe_infos.icmp_type_str();
        auto real_target = probe_infos.get_real_target4();
        try {
            auto pcap_file = build_pcap_name(options.pcap_dir_individual, icmp_type, real_target.to_string(), "INDIVIDUAL", minimum_probing_rate);
            algorithm_context.get_ostream() << analyse_individual_probes4(probe_infos, minimum_probing_rate, pcap_file, algorithm_context).str();
            pcap_file = build_pcap_name(options.pcap_dir_individual, icmp_type, real_target.to_string(), "INDIVIDUAL", triggering_rate);
            algorithm_context.get_ostream() << analyse_individual_probes4(probe_infos, triggering_rate, pcap_file, algorithm_context).str();
        } catch (const pcap_error & error) {
            std::cerr << error.what() << "\n";
        }

    }
    algorithm_context.set_triggering_rate(triggering_rate);
}


void rate_limit_individual_t::execute_individual_probes6(
        const NetworkInterface & sniff_interface,
        const probe_infos_t &probe_infos,
        int probing_rate,
        const std::string & output_dir_individual){
    // Probing rate represents the number of packets to send in 1 sec
    auto nb_probes = measurement_time * probing_rate;

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
    auto change_point = rate_limit_analyzer.compute_icmp_change_point6(real_target);
    auto transition_matrix_per_ip = rate_limit_analyzer.compute_loss_model6(real_target);

    auto line_ostream = build_output_line(
            probe_infos.get_real_target6(),
            "INDIVIDUAL",
            probing_rate,
            change_point,
            loss_rate,
            transition_matrix_per_ip.transition(0,0), transition_matrix_per_ip.transition(0,1), transition_matrix_per_ip.transition(1,0), transition_matrix_per_ip.transition(1,1),
            std::unordered_map<IPv6Address, double>());
    ostream << line_ostream.str();
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