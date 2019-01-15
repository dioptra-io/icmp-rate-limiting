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
#include <boost/variant.hpp>
#include <utils/variant_utils_t.hpp>

using namespace Tins;
using namespace utils;





void rate_limit_individual_t::execute_individual_probes(
        const NetworkInterface & sniff_interface,
        const probe_infos_t &probe_infos,
        int probing_rate,
        const std::string & output_dir_individual, int measurement_time){
    // Probing rate represents the number of packets to send in 1 sec
    auto nb_probes = measurement_time * probing_rate;


    auto pcap_file_name = std::string{""};
    auto icmp_type = probe_infos.icmp_type_str();
    auto real_target_str = probe_infos.get_real_target();

    pcap_file_name = build_pcap_name(output_dir_individual, icmp_type,
                                     real_target_str,
                                     "INDIVIDUAL",
                                     probing_rate);

    rate_limit_test_t rate_limit_test(nb_probes, probing_rate, sniff_interface,
                                                   std::vector<probe_infos_t>(1, probe_infos));
    rate_limit_test.set_pcap_file(pcap_file_name);
    std::cout << "Starting " << icmp_type <<  " for " << real_target_str << " with probing rate " << probing_rate <<  "...\n";
    rate_limit_test.start();

}

void rate_limit_individual_t::execute_individual_probes(
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



//    // Sort probes_infos to put first the candidates.
//    std::stable_sort(probes_infos.begin(), probes_infos.end(), [](const auto & probe_infos1, const auto & probe_infos2){
//        return static_cast<int>(probe_infos1.get_interface_type()) < static_cast<int>(probe_infos2.get_interface_type());
//    });

    // Progressively adapt the sending rate so the targeted loss rate is obtained on first candidate.

    for (const auto & probe_infos : probes_infos){

        // Use of boost variant in case C++ 17 is not available...
        boost::variant<IPv4Address, IPv6Address> real_target;
        std::unordered_map<std::string, int> & triggering_rates = algorithm_context.get_triggering_rates_by_ips();
        if (probe_infos.get_family() == PDU::PDUType::IP){
            real_target = probe_infos.get_real_target4();
        } else if (probe_infos.get_family() == PDU::PDUType::IPv6){
            real_target = probe_infos.get_real_target6();
        }

        auto real_target_str = boost::apply_visitor(visitor_t<to_string_functor_t>(to_string_functor_t()), real_target);


        auto icmp_type = probe_infos.icmp_type_str();

        if (options.is_custom_probing_rates){
            for (auto probing_rate: options.custom_probing_rates){

                execute_individual_probes(sniff_interface, probe_infos, probing_rate, options.pcap_dir_individual, options.measurement_time);
                std::this_thread::sleep_for(std::chrono::seconds(options.measurement_time + 1));
            }
            // Hack here to output the results of all rates for the need of the survey
            for (auto probing_rate : options.custom_probing_rates){
                auto pcap_file = build_pcap_name(options.pcap_dir_individual, icmp_type,
                                                 real_target_str, "INDIVIDUAL",
                                                 probing_rate);
                auto ostream = std::stringstream();
                if (probe_infos.get_family() == PDU::PDUType::IPv6){
                    ostream = analyse_individual_probes(probe_infos, probing_rate, pcap_file, algorithm_context);
                } else {
                    ostream = analyse_individual_probes(probe_infos, probing_rate, pcap_file, algorithm_context);
                }

                algorithm_context.get_ostream() << ostream.str();
            }
            return;
        }

        auto is_binary_search = false;
        auto probing_rate = starting_probing_rate;
        auto binary_search_iteration = 0;
        std::map<int, double> loss_rate_by_probing_rate;



        while(binary_search_iteration < maximum_binary_search_iteration) {

            if (probing_rate >= maximum_probing_rate || probing_rate < minimum_probing_rate) {
                std::cout << "No triggering probing rate found for the target loss rate interval ["
                          << target_loss_rate_interval.first
                          << ", " << target_loss_rate_interval.second << "] for " << real_target << "\n";
                break;
            }

            execute_individual_probes(sniff_interface, probe_infos, probing_rate, options.pcap_dir_individual, options.measurement_time);

            std::vector<probe_infos_t> v;
            v.push_back(probe_infos);
            auto rate_limit_analyzer = rate_limit_analyzer_t::build_rate_limit_analyzer_t_from_probe_infos(v);

            auto pcap_file = build_pcap_name(options.pcap_dir_individual, icmp_type, real_target_str, "INDIVIDUAL",
                                             probing_rate);
            rate_limit_analyzer.start(pcap_file);

            algorithm_context.get_analyzed_pcap_file()[pcap_file] = std::make_unique<rate_limit_analyzer_t>(rate_limit_analyzer);

            auto loss_rate = rate_limit_analyzer.compute_loss_rate(real_target_str);
            bool continue_probing = compute_next_probing_rate(loss_rate,
                                                              real_target_str,
                                                              loss_rate_by_probing_rate,
                                                              probing_rate,
                                                              starting_probing_rate,
                                                              triggering_rates,
                                                              target_loss_rate_interval,
                                                              is_binary_search,
                                                              binary_search_iteration);

            if (!continue_probing){
                std::this_thread::sleep_for(std::chrono::seconds(options.measurement_time + 1));
                break;
            }

            std::this_thread::sleep_for(std::chrono::seconds(options.measurement_time + 1));
        }

        if (!options.first_only){
            auto has_found_triggering_rate = triggering_rates.find(real_target_str) != triggering_rates.end();
            // In case no triggering rate has been found, take the closest value to the triggering rate of the first candidate
            // If it is the first candidate, take the probing rate that did bring the closest loss rate from the interval.
            if (!has_found_triggering_rate) {
                auto closest_probing_rate = find_closest_rate(probes_infos[0], loss_rate_by_probing_rate, target_loss_rate_interval);
                triggering_rates[real_target_str] = closest_probing_rate;
            }
            algorithm_context.get_loss_rates_by_ips()[real_target_str] = loss_rate_by_probing_rate;
//            algorithm_context.get_triggering_rates_by_ips()[real_target_str] = triggering_rates[real_target_str];
        }
        else{
            // Hack here to output the results of all rates for the need of the survey
            for (const auto & probing_rate_loss_rate : loss_rate_by_probing_rate){
                auto pcap_file = build_pcap_name(options.pcap_dir_individual, icmp_type, real_target_str, "INDIVIDUAL",
                                                 probing_rate_loss_rate.first);
                auto ostream = analyse_individual_probes(probe_infos, probing_rate_loss_rate.first, pcap_file, algorithm_context);
                algorithm_context.get_ostream() << ostream.str();
            }
        }

    }

    algorithm_context.set_triggering_rate_already_found(true);
}



std::stringstream rate_limit_individual_t::analyse_individual_probes(
        const probe_infos_t &probe_infos,
        int probing_rate,
        const std::string & pcap_file,
        algorithm_context_t & algorithm_context
){


    std::stringstream ostream;

    std::vector<probe_infos_t> probes_infos;
    probes_infos.push_back(probe_infos);

    auto  rate_limit_analyzer = rate_limit_analyzer_t::build_rate_limit_analyzer_t_from_probe_infos(probes_infos);
        auto it = algorithm_context.get_analyzed_pcap_file().find(pcap_file);
    if ( it != algorithm_context.get_analyzed_pcap_file().end()){
        rate_limit_analyzer = *(it->second);
    }
    else {
        // Start the analysis of responsiveness.
        rate_limit_analyzer.start(pcap_file);
        algorithm_context.get_analyzed_pcap_file()[pcap_file] = std::make_unique<rate_limit_analyzer_t>(rate_limit_analyzer);
    }

    auto real_target = probe_infos.get_real_target();
    // Extract loss rate.
    auto loss_rate = rate_limit_analyzer.compute_loss_rate(real_target);
    std::cout << "Loss rate: " << loss_rate << "\n";
    // Now extract relevant infos.
    auto change_point = rate_limit_analyzer.compute_icmp_change_point(real_target);
    auto transition_matrix_per_ip = rate_limit_analyzer.compute_loss_model(real_target);

    auto line_ostream = build_output_line(
            real_target,
            "INDIVIDUAL",
            probing_rate,
            change_point,
            loss_rate,
            transition_matrix_per_ip.transition(0,0), transition_matrix_per_ip.transition(0,1), transition_matrix_per_ip.transition(1,0), transition_matrix_per_ip.transition(1,1),
            std::unordered_map<std::string, double>());
    ostream << line_ostream.str();
    return ostream;
}

void rate_limit_individual_t::analyse_individual_probes(const std::vector <probe_infos_t> & probes_infos,
                                                        const std::pair<double, double> & target_loss_rate_interval,
                                                        const options_t & options,
                                                        algorithm_context_t & algorithm_context
){


    // Sort probes_infos to put first the candidates.
//    std::stable_sort(probes_infos.begin(), probes_infos.end(), [](const auto & probe_infos1, const auto & probe_infos2){
//        return static_cast<int>(probe_infos1.get_interface_type()) < static_cast<int>(probe_infos2.get_interface_type());
//    });

    if (options.first_only){
        auto first_candidate = probes_infos[0];
        for (int i = minimum_probing_rate; i < maximum_probing_rate; i *= 2){
            auto icmp_type = first_candidate.icmp_type_str();
            auto real_target = first_candidate.get_real_target();
            try {
                auto pcap_file = build_pcap_name(options.pcap_dir_individual, icmp_type, real_target,
                                                 "INDIVIDUAL", i);
                algorithm_context.get_ostream()
                        << analyse_individual_probes(first_candidate, i, pcap_file,
                                                     algorithm_context).str();
            }
            catch (const pcap_error & error) {
                std::cerr << error.what() << "\n";
            }
        }
        return;
    }


    for (const auto & probe_infos : probes_infos){
        int triggering_rate = 0;
        if (algorithm_context.is_triggering_rate_already_found()){
            triggering_rate = algorithm_context.get_triggering_rates_by_ips()[probe_infos.get_real_target()];
        }
        else {
            triggering_rate = find_triggering_rate(probe_infos, probes_infos, minimum_probing_rate, target_loss_rate_interval, options.pcap_dir_individual, "INDIVIDUAL", algorithm_context);
            algorithm_context.get_triggering_rates_by_ips()[probe_infos.get_real_target()] = triggering_rate;
        }

        auto icmp_type = probe_infos.icmp_type_str();
        auto real_target = probe_infos.get_real_target();
        try {
            auto pcap_file = build_pcap_name(options.pcap_dir_individual, icmp_type, real_target, "INDIVIDUAL", triggering_rate);
            algorithm_context.get_ostream() << analyse_individual_probes(probe_infos, triggering_rate, pcap_file, algorithm_context).str();
        } catch (const pcap_error & error) {
            std::cerr << error.what() << "\n";
        }

    }
}