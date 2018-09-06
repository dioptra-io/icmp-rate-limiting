//
// Created by System Administrator on 16/07/2018.
//

#include <iostream>

#include <string>
#include <sstream>
#include <algorithm>
#include <iterator>

#include <tins/tins.h>

#include "include/rate_limit_analyzer_t.hpp"
#include "include/rate_limit_plotter_t.hpp"
#include "include/icmp_trigger_probes_t.hpp"

#include "utils/struct_utils_t.hpp"
#include "utils/container_utils_t.hpp"
#include "utils/file_utils_t.hpp"
#include "utils/tins_utils_t.hpp"

#include "EasyBMP_1/EasyBMP.h"


using namespace boost::filesystem;
using namespace Tins;
using namespace utils;
namespace {


    struct sort_functor_t{
        enum class sort_by_t{
            TRIGGERING_PROBING_RATE, LOSS_RATE, PRR, PUU
        };

        sort_functor_t(sort_by_t sort_by):sort_by(sort_by){}

        bool operator()(const stats_t & stats_ip1, const stats_t & stats_ip2) const {
            if(sort_by == sort_by_t::TRIGGERING_PROBING_RATE){
                return stats_ip1.triggering_probing_rate < stats_ip2.triggering_probing_rate;
            } else if (sort_by == sort_by_t::LOSS_RATE){
                return stats_ip1.loss_rate < stats_ip2.loss_rate;
            } else if (sort_by == sort_by_t::PRR){
                return stats_ip1.burst_model.transition(0,0) < stats_ip2.burst_model.transition(0,0);
            } else if (sort_by == sort_by_t::PUU){
                return stats_ip1.burst_model.transition(1,1) < stats_ip2.burst_model.transition(1,1);
            }
            return false;
        }

    private:
        sort_by_t sort_by;
    };


    std::vector<int> init_probing_rates(){
        std::vector<int> rates;
        for (int i = 1; i < 14; ++i){
            rates.emplace_back(static_cast<int>(pow(2, i)));
        }
        return rates;
    }

    struct icmp_trigger_probe_type_t{
        interface_type_t interface_type;
        icmp_trigger_probes_t icmp_trigger_probes;
    };

    int start_power_of_2 = 1;
    int max_power_of_2 = 13;
    double loss_rate_threshold = 0.05;
}

int main (int argc, char*argv[]){

    if (argc < 1){
        std::cerr << "Usage <resource_dir>" << "\n";
        exit(1);
    }

    bool show_temporal = false;
    bool show_aggregate = false;
    bool show_raw = false;
    bool show_bmp_raw = false;
    bool show_bmp_by_ip = false;
    bool show_bmp_by_router = true;





    std::vector<int> probing_rates = init_probing_rates();

    std::vector<std::string> icmp_types;
    icmp_types.emplace_back("icmp_echo_reply");
//    icmp_types.emplace_back("icmp_unreachable");
//    icmp_types.emplace_back("icmp_ttl_exceeded");



    using stats_t = stats_t;



    // Set the different directories
    std::string routers_pcap_directory {"resources/multiple/"};
    path routers_path {"resources/routers/"};
    path pcap_directory(argv[1]);

    // Debug hack
//    ips.resize(20);
    // Here we find ips or routers
    std::vector<std::string> ips;

    if (!show_bmp_by_router){
        ips = extract_ips_from_filenames(pcap_directory);
    }
    // Reconstruct the matchers with from .router file

    using router_probes_t = std::vector<icmp_trigger_probe_type_t>;

    std::vector<router_probes_t> routers;

    if (show_bmp_by_router){
        // Fill routers
        for (directory_iterator itr(routers_path); itr != directory_iterator(); ++itr){

            std::string file_name{itr->path().string()};

            // Open the file and reconstruct the probes
            auto router_probes = build_icmp_trigger_probes_from_file(file_name,
                                                                     NetworkInterface::default_interface().ipv4_address());

            router_probes_t router_with_itype;

            for (int i = 0; i < router_probes.size(); ++i){
                if (i == router_probes.size() - 1){
                    router_with_itype.push_back(icmp_trigger_probe_type_t{interface_type_t ::WITNESS, router_probes[i]});
                } else {
                    router_with_itype.push_back(icmp_trigger_probe_type_t{interface_type_t ::CANDIDATE, router_probes[i]});
                }
            }

            routers.push_back(router_with_itype);
        }
    }


    for(const auto & icmp_type: icmp_types){
        std::cout << icmp_type << "\n";


        if (!show_bmp_by_router){
            // For show_aggregate
            std::unordered_map<IPv4Address, stats_t> stats_by_ip;

            // For show_bmp_raw
            std::unordered_map<IPv4Address, std::unordered_map<int, std::vector<responsive_info_probe_t>>> raw_data_by_ip_rate;

            auto ip_number = 0;
            for (const auto & test_ip: ips){
                std::cout << test_ip << " (" << ++ip_number << ")\n";
                // Init stats for plotting
                std::size_t v_size = max_power_of_2 - start_power_of_2 + 1;
                std::vector<double> losses(v_size, 0);
                std::vector<int> probing_rates(v_size, 0);
                std::vector<gilbert_elliot_t> bursts_probabilities(v_size);


                std::unordered_map<int, std::vector<responsive_info_probe_t>> raw_data_by_ip;

                for (int i = start_power_of_2; i < max_power_of_2; ++i){
                    int probing_rate = static_cast<int>(pow(2, i));
                    std::stringstream file_name;
                    file_name << icmp_type << "_" << test_ip << "_" << std::to_string(probing_rate) << ".pcap";


                    probing_style_t probing_style;
                    if (icmp_type == "icmp_ttl_exceeded"){
                        probing_style = probing_style_t::INDIRECT;
                    } else {
                        probing_style = probing_style_t::DIRECT;
                    }

                    std::string absolute_path = current_path().string() + "/" +pcap_directory.string() + file_name.str();

                    auto matchers = retrieve_matchers(test_ip, absolute_path);

                    // Build an analyzer with the informations found in the first packet.

                    rate_limit_analyzer_t icmp_analyzer{probing_style, matchers};

                    // Start the analysis
                    icmp_analyzer.start(absolute_path);

                    // Compute loss rate if necessary

                    auto loss_rate = icmp_analyzer.compute_loss_rate(test_ip);
                    auto burst_model_ip = icmp_analyzer.compute_loss_model(test_ip);

                    // For aggregate statistics
                    if (loss_rate > loss_rate_threshold){
                        stats_t stats_test_ip;
                        stats_test_ip.ip = test_ip;
                        stats_test_ip.loss_rate = loss_rate;
                        stats_test_ip.triggering_probing_rate = probing_rate;
                        stats_test_ip.burst_model = burst_model_ip;

                        auto it = stats_by_ip.find(test_ip);

//                    if (it != stats_by_ip.end() and stats_test_ip.triggering_probing_rate < it->second.triggering_probing_rate){
//                        stats_by_ip[test_ip] = stats_test_ip;
//                    } else {
//                        stats_by_ip.insert(std::make_pair(test_ip, stats_test_ip));
//                    }

                        stats_by_ip.insert(std::make_pair(test_ip, stats_test_ip));

                        if (show_aggregate and !show_raw and !show_temporal){
                            break;
                        }
                    }

                    // For bmp_raw
                    raw_data_by_ip.insert(std::make_pair(probing_rate, icmp_analyzer.get_raw_packets(test_ip)));


                    // For temporal evolution
                    losses[i-start_power_of_2] = loss_rate;
                    probing_rates[i-start_power_of_2] = probing_rate;
                    bursts_probabilities[i-start_power_of_2] = burst_model_ip;

                    if (show_raw){
                        auto raw_data = icmp_analyzer.get_raw_packets(test_ip);

                        icmp_analyzer.dump_time_series();
                        rate_limit_plotter_t raw_plotter;
                        raw_plotter.plot_raw(raw_data);
                    }
                }

                if (show_temporal){
                    rate_limit_plotter_t plotter;
                    plotter.plot_loss_rate_gilbert_eliott(losses, probing_rates, bursts_probabilities);
                }
                raw_data_by_ip_rate.insert(std::make_pair(test_ip, raw_data_by_ip));
            }
            if (show_aggregate){
                using plot_infos_t = rate_limit_plotter_t::plot_infos_t;
                plot_infos_t plot_infos;
                std::stringstream title_stream;
                title_stream << icmp_type << "_" <<  loss_rate_threshold << "_sort_triggering_probing_rate";
                plot_infos.title = title_stream.str();
                rate_limit_plotter_t plotter;
                plotter.plot_aggregate(stats_by_ip, plot_infos, sort_functor_t(sort_functor_t::sort_by_t::TRIGGERING_PROBING_RATE));

                title_stream.str("");
                title_stream << icmp_type << "_" <<  loss_rate_threshold << "_sort_loss_rate";
                plot_infos.title = title_stream.str();
                plotter.plot_aggregate(stats_by_ip, plot_infos, sort_functor_t(sort_functor_t::sort_by_t::LOSS_RATE));

                title_stream.str("");
                title_stream << icmp_type << "_" << loss_rate_threshold << "_sort_prr";
                plot_infos.title = title_stream.str();
                plotter.plot_aggregate(stats_by_ip, plot_infos, sort_functor_t(sort_functor_t::sort_by_t::PRR));

                title_stream.str("");
                title_stream << icmp_type << "_" << loss_rate_threshold << "_sort_puu";
                plot_infos.title = title_stream.str();
                plotter.plot_aggregate(stats_by_ip, plot_infos, sort_functor_t(sort_functor_t::sort_by_t::PUU));
            }

            if (show_bmp_raw){

                for (int i = 0; i < max_power_of_2; ++i){
                    std::unordered_map<IPv4Address, std::vector<responsive_info_probe_t>> bmp_map;
                    int probing_rate = static_cast<int>(pow(2, i+1));
                    // Transform data into the wanted container

                    for (const auto & raw_data_ip_rate: raw_data_by_ip_rate) {
                        auto it = raw_data_ip_rate.second.find(probing_rate);
                        if (it != raw_data_ip_rate.second.end()){
                            const auto & packets = raw_data_ip_rate.second.at(probing_rate);
                            bmp_map.insert(std::make_pair(raw_data_ip_rate.first, packets));
                        }
                    }
                    std::stringstream title_stream;
                    title_stream << "plots/raw/rates/" << icmp_type << "_" << probing_rate << ".bmp";
                    rate_limit_plotter_t plotter;
                    plotter.plot_bitmap_raw(bmp_map, title_stream.str());
                }

            }

            if (show_bmp_by_ip){
                for (const auto & raw_data_ip: raw_data_by_ip_rate){
                    std::string ip = raw_data_ip.first.to_string();
                    std::stringstream title_stream;
                    title_stream << "plots/raw/ips/" << icmp_type << "_" << ip << ".bmp";
                    rate_limit_plotter_t plotter;
                    plotter.plot_bitmap_ip(raw_data_ip, title_stream.str());
                }

            }

        }

        else{
            // Here we want to show correlation between ICMP rate limiting for multiple interfaces
            // Debug hack here to only take 2 aliases.

            for (auto & router_probes: routers){
                router_probes_t copy_vec;
                std::copy(router_probes.begin(), router_probes.begin() + 2, std::back_inserter(copy_vec));
                copy_vec.push_back(*(router_probes.end()-1));

                router_probes = copy_vec;
            }





            for (const auto & router_probes: routers){

//                if (router_probes[1].icmp_trigger_probes.test_address() != "112.174.236.22"){
//                    continue;
//                }

                std::stringstream pcap_file_prefix;
                pcap_file_prefix << icmp_type << "_";



                std::unordered_map<IPv4Address, std::unordered_map<int, std::vector<responsive_info_probe_t>>> raw_routers_all_rates;
                std::unordered_map<IPv4Address, std::unordered_map<int, std::vector<responsive_info_probe_t>>> raw_witnesses_all_rates;

                probing_style_t probing_style {probing_style_t::DIRECT};

                std::unordered_map<IPv4Address, IP> matchers;

                std::vector<IPv4Address> candidates;
                std::vector<IPv4Address> witnesses;

                for(const auto & ip_probes : router_probes){




                    if (icmp_type == "icmp_ttl_exceeded"){
                        matchers.insert(std::make_pair(ip_probes.icmp_trigger_probes.test_address(), ip_probes.icmp_trigger_probes.get_icmp_ttl_exceeded()));
                        if (probing_style == probing_style_t::DIRECT){
                            probing_style = probing_style_t::INDIRECT;
                        }
                    }

                    if (ip_probes.interface_type == interface_type_t::CANDIDATE){
                        // Init the aggregate rates maps
                        raw_routers_all_rates.insert(std::make_pair(ip_probes.icmp_trigger_probes.test_address(),
                                                                    std::unordered_map<int, std::vector<responsive_info_probe_t>>()));
                        candidates.emplace_back(ip_probes.icmp_trigger_probes.test_address());
                    } else {
                        witnesses.emplace_back(ip_probes.icmp_trigger_probes.test_address());
                        raw_witnesses_all_rates.insert(std::make_pair(ip_probes.icmp_trigger_probes.test_address(),
                                                                      std::unordered_map<int, std::vector<responsive_info_probe_t>>()));
                    }
                    pcap_file_prefix << ip_probes.icmp_trigger_probes.test_address() << "_";
                }
                // Launch analysis for each probing rate

                for (const auto & rate : probing_rates){
                    std::stringstream pcap_file;
                    pcap_file << routers_pcap_directory <<  pcap_file_prefix.str() << std::to_string(rate) << ".pcap";

                    std::cout << "Plotting rate: " << rate << "\n";

                    try{
                        rate_limit_analyzer_t analyzer {probing_style, matchers};
                        std::string pcap_file_str = pcap_file.str();
//                        if ("resources/mutiple/icmp_unreachable_193.51.177.39_193.51.180.61_193.51.177.26_1024.pcap" == pcap_file_str){
//                            std::cout << "TRUE\n";
//                        }
                        analyzer.start(pcap_file_str);
                        auto triggering_rates_by_ip = analyzer.compute_icmp_triggering_rate();
                        for (const auto & triggering_rates : triggering_rates_by_ip){
                            std::cout << triggering_rates.first << ": (" << triggering_rates.second.first << ", " << triggering_rates.second.second << ")\n";
                        }

                        rate_limit_plotter_t plotter;

                        using responsiveness_ip_t = std::unordered_map<IPv4Address, std::vector<responsive_info_probe_t>>;

                        responsiveness_ip_t responsiveness_ip_candidates;
                        for(const auto & candidate : candidates) {
                            auto raw_packets = analyzer.get_raw_packets(candidate);
                            responsiveness_ip_candidates.insert(std::make_pair(candidate, raw_packets));
                            raw_routers_all_rates.at(candidate).insert(std::make_pair(rate, raw_packets));
                        }

                        responsiveness_ip_t responsiveness_ip_witnesses;
                        for(const auto & witness : witnesses) {
                            auto raw_packets = analyzer.get_raw_packets(witness);
                            responsiveness_ip_witnesses.insert(std::make_pair(witness, raw_packets));
                            raw_witnesses_all_rates.at(witness).insert(std::make_pair(rate, raw_packets));
                        }
//                        std::stringstream output_file;
//                        output_file << "plots/raw/routers/" << pcap_file_prefix.str() << rate << ".bmp";
//                        plotter.plot_bitmap_router_rate(responsiveness_ip_candidates, responsiveness_ip_witnesses, output_file.str());

                    } catch (const pcap_error & e){
                        std::cerr << e.what() << "\n";
                    }





                }

                std::stringstream output_file;
                output_file << "plots/raw/routers/" << pcap_file_prefix.str() << ".bmp";

                rate_limit_plotter_t plotter;
                plotter.plot_bitmap_router(raw_routers_all_rates, raw_witnesses_all_rates, output_file.str());

                std::stringstream correlation_title;
                correlation_title << "plots/raw/routers/" << pcap_file_prefix.str() << ".correlation";
                plotter.plot_correlation_matrix(raw_routers_all_rates, raw_witnesses_all_rates, correlation_title.str());
            }
        }
    }
}

