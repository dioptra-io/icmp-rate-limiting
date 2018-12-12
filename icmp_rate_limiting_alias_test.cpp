//
// Created by System Administrator on 29/08/2018.
//
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <unordered_map>

#include <cmath>

#include <boost/program_options.hpp>

#include <tins/tins.h>

#include <probe_infos_t.hpp>
#include <rate_limit_test_t.hpp>
#include <rate_limit_plotter_t.hpp>
#include <rate_limit_individual_t.hpp>
#include <rate_limit_group_t.hpp>
#include <icmp_trigger_probes_t.hpp>
#include <utils/file_utils_t.hpp>
#include <utils/network_utils_t.hpp>


using namespace Tins;
using namespace utils;
namespace {


    auto target_loss_rate_interval = std::pair<double, double> {0.05, 0.20};
    auto starting_probing_rate = minimum_probing_rate;
    std::vector<int> custom_rates{1000};

}




int main(int argc, char * argv[]){
    /**
    * END TO END ALGORITHM TO DETERMINE IF TWO ADDRESSES ARE ALIASES.
    * - Probe each interface separately with progressive rates until the targeted loss rate is triggered.
    * - Determine the rate where the responding behaviour changes for each interface (Technique: compute loss rates on intervals)
    * - Probe trios of interfaces with progressive rates, two are the candidates, one is the witness.
    * - Determine the rate where the responding behaviour changes.
    * - Compute correlation between candidates/witness
    * - Probe trios of interfaces with different rates
    * - Compute loss rate
    * - Conclude: if the changing rates are different from single candidate
    * to two candidates and the correlation is high between candidates, and low
    * between candidates and witness, conclude that they are aliases.
    *
    */

    // The format of the input file should be the following:
    // GROUP_ID, ADDRESS_FAMILY, PROBING_TYPE (DIRECT, INDIRECT), PROTOCOL (tcp, udp, icmp), INTERFACE_TYPE (CANDIDATE, WITNESS),
    // REAL_ADDRESS, PROBING_ADDRESS, FLOW_ID (v6), SRC_PORT(v4) , DST_PORT(v4).

    namespace po = boost::program_options;

    std::string help_message = "";

    options_t options;
    auto targets_file_path = std::string("");
    options.pcap_dir_individual  = "resources/pcap/individual/";
    options.pcap_dir_groups = "resources/pcap/groups/";

    std::string pcap_prefix {""};
    std::string output_file;

    // Declare the supported options.
    po::options_description desc("Options");
    desc.add_options()
            ("help,h", help_message.c_str())
            ("targets-file,t", po::value<std::string>(), "Format is GROUP_ID, ADDRESS_FAMILY, PROBING_TYPE (DIRECT, INDIRECT), PROTOCOL (tcp, udp, icmp), INTERFACE_TYPE (CANDIDATE, WITNESS),"\
                                                     "REAL_ADDRESS, PROBING_ADDRESS, FLOW_ID (v6), SRC_PORT(v4) , DST_PORT(v4)." )
            ("pcap-individual-dir,i", po::value<std::string>(), "directory for individual probing pcap files")
            ("pcap-group-dir,g", po::value<std::string>(), "directory for group probing pcap files")
            ("pcap-prefix,x", po::value<std::string>(), "pcap_prefix of pcap files")
            ("output-file,o", po::value<std::string>(), "output file of the analysis")
            ("group-only,G", "only do group probing")
            ("individual-only,I", "only do individual probing")
            ("first-only,f", "only probe first candidate")
            ("analyse-only,a", "do not probe, only start analysis")
            ("use-individual,u", "use individual for group analyse triggering rate")
            ("use-group,U", "use group for group analyse triggering rate")
            ("probe-only,p", "do not analyse, only probe")
            ("custom-probing-rates,c", "Use custom probing rates");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << "\n";
        return 1;
    }

    if (vm.count("targets-file")) {
        targets_file_path = vm["targets-file"].as<std::string>();
        std::cout << "Targets file was set to "
             << targets_file_path << "\n";


    } else {
        std::cerr << "Missing targets file. Exiting...\n";
        exit(1);
    }

    if (vm.count("pcap-individual-dir")) {
        options.pcap_dir_individual = vm["pcap-individual-dir"].as<std::string>();
        std::cout << "pcap individual dir set to  "
                  << options.pcap_dir_individual << "\n";


    }

    if (vm.count("pcap-group-dir")) {
        options.pcap_dir_groups = vm["pcap-group-dir"].as<std::string>();
        std::cout << "pcap groups dir set to  "
                  << options.pcap_dir_groups << "\n";
    }

    if (vm.count("pcap-prefix")) {
        pcap_prefix = vm["pcap-prefix"].as<std::string>();
        std::cout << "pcap prefix dir set to  "
                  << pcap_prefix << "\n";

        options.pcap_dir_individual += pcap_prefix;
        options.pcap_dir_groups += pcap_prefix;
    }

    if (vm.count("output-file")) {
        output_file = vm["output-file"].as<std::string>();
        std::cout << "output file set to  "
                  << output_file<< "\n";
    }

    if (vm.count("individual-only")){
        options.individual_only = true;
        std::cout << "Only individual probing will be done.\n";
    }
    if (vm.count("individual-only")){
        options.first_only = true;
        std::cout << "Only first candidate will be probed.\n";
    }

    if (vm.count("group-only")){
        options.group_only = true;
        std::cout << "Only group probing will be done.\n";
    }
    if (vm.count("analyse-only")) {
        options.analyse_only = true;
        std::cout << "Only analyse will be done.\n";
    }

    if (vm.count("use-individual")) {
        options.use_individual_for_analyse = true;
        std::cout << "Individual pcap files will be used for group analyse.\n";
    } else if (vm.count("use-group")) {
        options.use_group_for_analyse = true;
        std::cout << "Group pcap files will be used for group analyse.\n";
    } else {
        if (vm.count("group-only") && vm.count("analyse-only")) {
            std::cerr << "Please choose which pcap files (individual or group) will be used for analyse."
                         "Use -u or -U option\n";
            exit(1);
        } else {
            options.use_individual_for_analyse = true;
        }
    }

    if (vm.count("probe-only")) {
        options.probe_only = true;
        std::cout << "Only probing will be done.\n";
    }
    if (vm.count("custom-probing-rates")) {
        options.is_custom_probing_rates = true;

        // No parameter atm
        for (int i = 1000; i <= 4000; i += 250 ){
            options.custom_probing_rates.push_back(i);
        }
        std::cout << "Custom probing rates will be used.\n";
    }


    auto probes_infos = parse_input_file(targets_file_path.c_str());


    /**
     * Initialize default values
     */

    auto max_probing_rate = 10000;


    /**
     * Initialize aliases
     */
    std::vector<std::vector<probe_infos_t>> aliases;


    /**
     * Initialize output stream
     */


    std::stringstream ostream;

    /**
     * Intialize algorithm context
     */
    algorithm_context_t algorithm_context;



    // Individual probing
    rate_limit_individual_t rate_limit_individual;
    rate_limit_group_t rate_limit_group;
    rate_limit_group_t rate_limit_group_dpr;
    if (!options.analyse_only){

        if (!options.group_only){
            std::cout << "Proceeding to probing individual phase with progressive probing rate\n";
            rate_limit_individual.execute_individual_probes(probes_infos,
                    starting_probing_rate,
                                                                               target_loss_rate_interval,
                                                                               options,
                                                                               algorithm_context);
            if (!options.individual_only){
                std::this_thread::sleep_for(std::chrono::seconds(measurement_time + 1));
            }
        }

        if (!options.individual_only){
            // Group probing same rate
            std::cout << "Proceeding to probing groups phase with same probing rate\n";
            rate_limit_group.execute_group_probes(probes_infos,
                                                   target_loss_rate_interval,
                                                   "GROUPSPR",
                                                   options,
                                                   algorithm_context);
            std::this_thread::sleep_for(std::chrono::seconds(measurement_time + 1));
            std::cout << "Proceeding to probing groups phase with different probing rate\n";
            rate_limit_group_dpr.execute_group_probes(probes_infos,
                                                       target_loss_rate_interval,
                                                       "GROUPDPR",
                                                       options,
                                                       algorithm_context);
        }

    }
    // Analysis
    if(!options.probe_only){
        if (!options.group_only){
            rate_limit_individual.analyse_individual_probes(
                    probes_infos,
                    target_loss_rate_interval,
                    options,
                    algorithm_context);
            algorithm_context.set_triggering_rate_already_found(true);
        }
        if (!options.individual_only){
            rate_limit_group.analyse_group_probes(probes_infos,
                                                   target_loss_rate_interval,
                                                   "GROUPSPR",
                                                   options,
                                                   algorithm_context);
            algorithm_context.set_triggering_rate_already_found(true);
            rate_limit_group_dpr.analyse_group_probes(probes_infos,
                                                       target_loss_rate_interval,
                                                       "GROUPDPR",
                                                       options,
                                                       algorithm_context);
        }
    }
    std::ofstream outfile (output_file);
    outfile << algorithm_context.get_ostream().str() << "\n";

    std::cout << algorithm_context.get_ostream().str();

}

