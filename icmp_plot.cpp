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

#include "utils/struct_utils_t.hpp"
#include "utils/container_utils_t.hpp"
#include "utils/file_utils_t.hpp"

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


    int start_power_of_2 = 1;
    int max_power_of_2 = 13;
    int max_probing_rate = static_cast<int>(pow(2, 14));
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
    bool show_bmp_by_ip = true;
    // Plot the results
    path pcap_directory(argv[1]);

    std::vector<std::string> ips = extract_ips_from_filenames(pcap_directory);




    std::vector<std::string> icmp_types;
    icmp_types.emplace_back("icmp_unreachable");
    icmp_types.emplace_back("icmp_echo_reply");
    icmp_types.emplace_back("icmp_ttl_exceeded");


    using stats_t = stats_t;

    // Debug hack
//    ips.resize(20);

    for(const auto & icmp_type: icmp_types){
        std::cout << icmp_type << "\n";

        // For show_aggregate
        std::unordered_map<IPv4Address, stats_t> stats_by_ip;

        // For show_bmp_raw
        using responsive_info_probe_t = rate_limit_plotter_t::responsive_info_probe_t;
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
                std::stringstream file_name;
                file_name << icmp_type << "_" << test_ip << "_" << std::to_string(static_cast<int>(pow(2,i))) << ".pcap";


                std::unordered_map<IPv4Address, IP> matchers;
                rate_limit_analyzer_t::probing_style_t probing_style;

                std::string absolute_path = current_path().string() + "/resources/" + file_name.str();
                try{
                    FileSniffer sniffer(absolute_path);
                    Packet first_packet {sniffer.next_packet()};
                    // The first packet is supposed to be a probe packet.
                    if (first_packet.pdu() != nullptr){
                        // Extract the protocol and type infos.
                        auto first_pdu = first_packet.pdu();
                        auto ip = first_pdu->find_pdu<IP>();
                        auto udp = ip->find_pdu<UDP>();
                        if (udp != nullptr){
                            // This is udp, figure out if this was direct or indirect by looking at the destination
                            IP probe = IP(ip->dst_addr(), ip->src_addr()) /UDP(udp->dport(), udp->dport());
                            probe.ttl(ip->ttl());
                            if (ip->dst_addr() == IPv4Address(test_ip)){
                                // We are in a direct test.
                                probing_style = rate_limit_analyzer_t::probing_style_t::DIRECT;

                                matchers.insert(std::make_pair(ip->dst_addr(), probe));
                            } else{
                                probing_style = rate_limit_analyzer_t::probing_style_t::INDIRECT;
                                matchers.insert(std::make_pair(test_ip, probe));
                            }

                        } else {
                            auto icmp = ip->find_pdu<ICMP>();
                            if (icmp != nullptr){
                                IP probe = IP(ip->dst_addr(), ip->src_addr())/ ICMP();
                                probe.ttl(ip->ttl());
                                matchers.insert(std::make_pair(ip->dst_addr(), probe));
                            } else {
                                std::cerr << "Can not recognize the type of probing.\n";
                            }
                        }
                    }

                    // Build an analyzer with the informations found in the first packet.

                    rate_limit_analyzer_t icmp_analyzer{probing_style, matchers};

                    // Start the analysis
                    icmp_analyzer.start(absolute_path);
                    int probing_rate = static_cast<int>(pow(2, i));

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
                } catch (const pcap_error & e) {
                    std::cerr << e.what() << "\n";
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

//
//            for (directory_iterator itr(pcap_directory); itr!=directory_iterator(); ++itr) {
//
//
//                // Parse the file_name to retrieve probing type.
//                std::string file_name {itr->path().filename().string()};
//
//                auto ip_match = file_name.find(ip);
//                if (ip_match == std::string::npos){
//                    continue;
//                }
//
//                auto icmp_type_match = file_name.find(icmp_type);
//                if (icmp_type_match == std::string::npos){
//                    continue;
//                }
//
//
////                std::cout << file_name << "\n";
//
//                std::vector<std::string> tokens;
//                split(file_name, tokens, '_');
//
//                std::stringstream icmp_type_stream;
//                icmp_type_stream << tokens[0] << "_" << tokens[1];
//                // Test against different ICMP type
//                std::string test_ip;
//                int probing_rate = 0;
//                if (std::isdigit(tokens[2][0])){
//                    test_ip = tokens[2];
//                    probing_rate = std::stoi(tokens[3]);
//                } else {
//                    icmp_type_stream << "_" << tokens[2];
//                    test_ip = tokens[3];
//                    probing_rate = std::stoi(tokens[4]);
//                }


//                std::cout << "ICMP type: " << icmp_type_stream.str() << "\n";
//                std::cout << "IP address: " << test_ip << "\n";
//                std::cout << "Probing rate: " << probing_rate << "\n";

    }
}

