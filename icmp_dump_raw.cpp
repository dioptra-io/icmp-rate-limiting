//
// Created by System Administrator on 22/10/2018.
//
#include <string>
#include <rate_limit_analyzer_t.hpp>
#include <rate_limit_plotter_t.hpp>
#include <utils/container_utils_t.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>


using namespace Tins;
using namespace utils;
/**
 * This binary just serialize in a json list format the responsiveness of an interface
 * @param argc
 * @param argv
 * @return
 */
using namespace utils;
int main (int argc, char **argv){


    std::string pcap_dir {argv[1]};


    // Parse pcap file to build matchers for analyzer
    std::vector<std::string> tokens;


    using namespace boost::filesystem;


    path pcap_dir_p (argv[1]);
    std::map<double, std::pair<int, std::vector<int>>> raw_time_series_by_ip;
    std::map<double, std::pair<int, std::vector<responsive_info_probe_t >>> raw_time_series_by_ip_individual;

    std::map<double, int> t11_cp;
    if(is_directory(pcap_dir_p)) {
        std::cout << pcap_dir_p << " is a directory containing:\n";

        for(boost::filesystem::directory_entry& entry : boost::make_iterator_range(directory_iterator(pcap_dir_p), {})) {
            std::cout << entry << "\n";
            std::string pcap_file = entry.path().string();
            boost::split(tokens, pcap_file, [](char c) { return c == '_'; });

            if (pcap_file.find("INDIVIDUAL") != std::string::npos){
                auto candidate = IPv4Address(tokens[3]);
                std::unordered_map<IPv4Address, IP> matchers;
                matchers.insert(std::make_pair(candidate, IP(candidate)));
                rate_limit_analyzer_t analyzer{probing_style_t::DIRECT, matchers};
                analyzer.start(pcap_file);
                // Sort by transition_1_1
                auto transition_matrix = analyzer.compute_loss_model(candidate.to_string());
                auto transition_1_1 = transition_matrix.transition(1, 1);
                auto cp = analyzer.compute_change_point(candidate.to_string());
                t11_cp.insert(std::make_pair(transition_1_1, cp));


                raw_time_series_by_ip_individual.insert(
                        std::make_pair(transition_1_1,std::make_pair(cp, analyzer.get_raw_packets(candidate.to_string()))));
            }

            if (pcap_file.find("DPR") != std::string::npos){
                // We are testing high low comparison
                auto high_rate_candidate = IPv4Address(tokens[4]);
                auto low_rate_candidate = IPv4Address(tokens[5]);
                std::unordered_map<IPv4Address, IP> matchers;
                matchers.insert(std::make_pair(high_rate_candidate, IP(high_rate_candidate)));
                matchers.insert(std::make_pair(low_rate_candidate, IP(low_rate_candidate)));
                rate_limit_analyzer_t analyzer{probing_style_t::DIRECT, matchers};
                analyzer.start(pcap_file);
                auto adjust_ts = analyzer.adjust_time_series_length(high_rate_candidate.to_string(), low_rate_candidate.to_string());

                auto cp_high = analyzer.compute_change_point(adjust_ts.first, rate_limit_analyzer_t::change_point_type_t::MEAN);
                auto cp_low = analyzer.compute_change_point(adjust_ts.second, rate_limit_analyzer_t::change_point_type_t::MEAN) ;

                auto high_rate_transition_matrix = analyzer.compute_loss_model(high_rate_candidate.to_string());
                auto high_rate_transition_1_1 = high_rate_transition_matrix.transition(1, 1);

                auto low_rate_transition_matrix = analyzer.compute_loss_model(low_rate_candidate.to_string());
                auto low_rate_transition_1_1 = low_rate_transition_matrix.transition(1, 1);

                auto correlation = analyzer.correlation_high_low(high_rate_candidate.to_string(), low_rate_candidate.to_string());
                std::cout << high_rate_candidate << ": " << high_rate_transition_1_1 << "\n";
                std::cout << low_rate_candidate << ": " << low_rate_transition_1_1 << "\n";

                std::cout << "Correlation: " << correlation << "\n";
                if (correlation < 0){
                    std::cout << high_rate_candidate << ", " << low_rate_candidate << "\n";
                    std::cout << "wow" << "\n";
                }
                t11_cp.insert(std::make_pair(correlation, cp_high));
//                t11_cp.insert(std::make_pair(low_rate_transition_1_1, cp_low));

                raw_time_series_by_ip.insert(
                        std::make_pair(correlation,std::make_pair(cp_high, adjust_ts.first)));
                raw_time_series_by_ip.insert(
                        std::make_pair(correlation + 0.0001,std::make_pair(cp_low, adjust_ts.second)));
            }
        }

    }
    rate_limit_plotter_t<IPv4Address> plotter;

    plotter.plot_bitmap_raw_with_changepoint(raw_time_series_by_ip, "/Users/kevinvermeulen/Documents/Papers/CCR/ccr-template/figures/test_cp_0.05.bmp");
    plotter.plot_bitmap_raw_with_changepoint(raw_time_series_by_ip_individual, "/Users/kevinvermeulen/Documents/Papers/CCR/ccr-template/figures/test_cp_individual_0.05.bmp");
    for (const auto & t_cp : t11_cp){
        std::cout << t_cp.first << ", " << t_cp.second <<  "\n";
    }
}

//    auto candidate1 = IPv4Address(tokens[4]);
//    auto candidate2 = IPv4Address(tokens[5]);
//    auto witness = IPv4Address(tokens[6]);
//    std::unordered_map<IPv4Address, IP> matchers;
//    matchers.insert(std::make_pair(candidate1, IP(candidate1)));
//    matchers.insert(std::make_pair(candidate2, IP(candidate2)));
//    matchers.insert(std::make_pair(witness, IP(witness)));
//    rate_limit_analyzer_t analyzer {utils::probing_style_t::DIRECT, matchers};
//
//    analyzer.start(pcap_file);
//
//
//    std::unordered_map<IPv4Address, std::vector<responsive_info_probe_t>> raw_time_series_by_ip;
//    raw_time_series_by_ip.insert(std::make_pair(candidate1, analyzer.get_raw_packets(candidate1.to_string())));
//    rate_limit_plotter_t<IPv4Address> plotter;
//
//    plotter.plot_bitmap_raw(raw_time_series_by_ip, "/Users/kevinvermeulen/Documents/Papers/CCR/ccr-template/figures/test.bmp");
//    std::cout << analyzer.serialize_raw() << "\n";
