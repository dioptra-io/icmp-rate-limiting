#include <iostream>
#include <chrono>

#include <tins/tins.h>
#include <thread>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <dnet.h>
#include <chrono>
#include <thread>
#include <sstream>
#include <random>
#include <fstream>


#include <boost/filesystem.hpp>


#include <utils/file_utils_t.hpp>
#include <utils/tins_utils_t.hpp>
#include <utils/container_utils_t.hpp>
#include <sender_t.hpp>
#include <rate_limit_test_t.hpp>
#include <icmp_trigger_probes_t.hpp>


using namespace Tins;

using namespace utils;

using namespace boost::filesystem;
namespace {

    uint8_t  test_ttl = 7;

    std::pair<bool, IPv4Address> is_responsive(const IPv4Address & dst_ip, const IPv4Address src_ip, ICMP::Flags icmp_type){
        PacketSender test_sender;
        SnifferConfiguration configuration;
        configuration.set_immediate_mode(true);
        configuration.set_filter("icmp or (dst " + dst_ip.to_string()+ ")");
        Sniffer sniffer(NetworkInterface::default_interface().name(), configuration);


        // Start sniffing

        std::vector<Packet> sniffed_packets;
        std::atomic<bool> running = true;
        auto handler = [&sniffed_packets, &running](Packet & packet){
            sniffed_packets.push_back(packet);
            return running.load();
        };

        std::thread sniff_thread(
                [&]() {
                    sniffer.sniff_loop(handler, 3);
                }
        );

        // Find the TTL-Exceeding message at TTL 6

        auto icmp_triggering_probe = build_icmp_triggering_probe(dst_ip, src_ip, 24000, 33435, test_ttl, icmp_type);


        test_sender.send(icmp_triggering_probe);
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        running = false;
        test_sender.send(icmp_triggering_probe);
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        sniff_thread.join();
        if (!sniffed_packets.empty()) {
            for (const auto & sniffed_packet : sniffed_packets){
                auto ip_response = sniffed_packet.pdu()->find_pdu<IP>();
                auto icmp_response = ip_response->find_pdu<ICMP>();
                if (icmp_response != nullptr) {
                    if (icmp_type == icmp_response->type()) {
                        auto response_ip = ip_response->src_addr();
                        return std::make_pair(true, response_ip);
                    }
                }
            }
        }
        return std::make_pair(false, IPv4Address());
    }

    IP find_probe_from_file(const std::string & input_dir, const IPv4Address & ip, const std::string & icmp_type, int probing_rate){
        // First ttl-exceeded file
        std::stringstream icmp_file;
        icmp_file << input_dir << icmp_type << "_" << ip.to_string() << "_" << probing_rate << ".pcap";

        auto probes_by_ip = retrieve_matchers(ip, icmp_file.str());
        IP probe = probes_by_ip.at(ip);
        return probe;
    }

}

int main(int argc, char ** argv) {

    if (argc < 1){
        fprintf(stderr, "Usage: <addresses> <candidates> <ports> <ttl> <options>");
    }

    auto sniff_interface = NetworkInterface::default_interface();


    // Probing rate for before and after interfaces (if set)

    // The testing suite consist in 3 tests, 1 per ICMP message type that can be rate-limited: Indirect (TTL-Exceeded) messages and Direct probing (Destination Unreachable or Echo reply)

    // Progressively increase the sending rate (log scale)
    auto max_probing_rate = 10000;

    bool is_random_addresses = false;
    bool is_addresses_from_file = false;
    bool is_multiple_addresses_from_file = true;

    using alias_test_t = std::vector<icmp_trigger_probes_t>;

    std::vector<alias_test_t> alias_tests;

    std::vector<icmp_trigger_probes_t> test_addresses;
    if (is_random_addresses){
        // Find 1000 random addresses from traceroute TTL-exceeded
        std::random_device rd;
        std::mt19937 mt(rd());
        std::uniform_int_distribution<int> distribution(1,254);

        while (test_addresses.size() < 100){
            // Generate a random address
            std::vector<int> bytes(4, 0);
            std::stringstream address_stream;
            for (int i = 0; i < bytes.size(); ++i) {
                bytes[i] = distribution(mt);
                address_stream << bytes[i];
                if (i != bytes.size() - 1){
                    address_stream << ".";
                }
            }

            if (bytes[0] == 0){
                continue;
            }
            // Find the TTL-Exceeding message at TTL 6

            auto address = address_stream.str();

            auto is_ttl_exceeded_responsive = is_responsive(address, sniff_interface.ipv4_address(), ICMP::Flags::TIME_EXCEEDED);
            if (is_ttl_exceeded_responsive.first){
                auto target_ip = is_ttl_exceeded_responsive.second;
                auto is_traceroutable = is_responsive(target_ip, sniff_interface.ipv4_address(), ICMP::DEST_UNREACHABLE);
                auto is_pingable = is_responsive(target_ip, sniff_interface.ipv4_address(), ICMP::ECHO_REPLY);

                if (is_pingable.first or is_traceroutable.first){
                    auto ttl_exceeded_probe = build_icmp_triggering_probe(address, sniff_interface.ipv4_address(), 24000, 33435, test_ttl, ICMP::TIME_EXCEEDED);
                    auto dst_unreachable_probe = build_icmp_triggering_probe(target_ip, sniff_interface.ipv4_address(),  24000, 33435, 0, ICMP::DEST_UNREACHABLE);
                    auto echo_reply_probe = build_icmp_triggering_probe(target_ip, sniff_interface.ipv4_address(), 0, 0, 0, ICMP::Flags::ECHO_REPLY);

                    icmp_trigger_probes_t candidate_to_add {ttl_exceeded_probe, dst_unreachable_probe, echo_reply_probe};
                    auto already_in_test_addresses = std::find(test_addresses.begin(), test_addresses.end(), candidate_to_add);
                    if (already_in_test_addresses == test_addresses.end()){
                        test_addresses.push_back(std::move(candidate_to_add));
                    }
                }
            }

            if (test_addresses.size() %5 == 0){
                std::cout << "Found " << test_addresses.size() << " addresses to test on 100 expected." << "\n";
            }
        }
//

    }

    std::string input_dir {"resources/1/"};
//    std::string output_dir {"resources/2/"};

    if (is_addresses_from_file){
        path address_dir(input_dir);
        path reprobe_address_dir(output_dir);

        auto ip_addresses_str = extract_ips_from_filenames(address_dir);
        for (const auto & ip_address_str : ip_addresses_str){
            // if all probes already in 2/ skip this interface
            std::stringstream existing_file;
            existing_file << output_dir  << "icmp_ttl_exceeded_" << ip_address_str << "_" << std::to_string(8192) << ".pcap";
            if (exists(path(existing_file.str()))){
                continue;
            }

            // Find the corresponding pcap files 2.

            // First ttl-exceeded probe
            IP ttl_exceeded_probe = find_probe_from_file(address_dir.string(),ip_address_str, "icmp_ttl_exceeded", 2);
            std::cout << ttl_exceeded_probe.dst_addr() << "\n";
            // Second echo-reply probe
            IP echo_reply_probe = find_probe_from_file(address_dir.string(), ip_address_str, "icmp_echo_reply", 2);
            // Third destination unreachable file
            IP dest_unreachable_probe = find_probe_from_file(address_dir.string(), ip_address_str, "icmp_unreachable", 2);

            test_addresses.emplace_back(ttl_exceeded_probe, dest_unreachable_probe, echo_reply_probe);
        }
    }



    if (is_multiple_addresses_from_file){
        path address_dir("resources/routers/");

        path pcap_router("resources/multiple");

        // Parse the .router files, one triplet by router.
        for (directory_iterator itr(address_dir); itr!=directory_iterator(); ++itr){
            alias_test_t alias_test;

            std::string file_name {itr->path().string()};

            // Debug hack
//            if (file_name != std::string("resources/routers/38.46.191.67_0.router")){
//                continue;
//            }

            alias_test = build_icmp_trigger_probes_from_file(file_name, sniff_interface.ipv4_address());

            // NOT DUPLICATE EXPERIMENT.
            auto file_exists = std::find_if(directory_iterator(pcap_router), directory_iterator(), [&alias_test](const auto & file){
                // Check that we have completed all the experiments for this alias set
                auto file_name = file.path().string();
                auto test_address = alias_test[0].test_address();
//                if (file_name.find(test_address) != std::string::npos){
//                    if (file_name.find("8192") != std::string::npos){
//                        if (file_name.find("icmp_ttl_exceeded") != std::string::npos){
//                            return true;
//                        }
//                    }
//                }
                return file_name.find(test_address) != std::string::npos && file_name.find("8192") != std::string::npos && file_name.find("icmp_ttl_exceeded") != std::string::npos;
            });

            if (file_exists != directory_iterator()){
                continue;
            }

            // Hack here to just keep the 2 first and the witness
            alias_test_t test_2_and_witness (alias_test.begin(), alias_test.begin()+2);
            test_2_and_witness.push_back(*(alias_test.end()-1));

            alias_tests.push_back(test_2_and_witness);
        }

    }

    if(is_random_addresses or is_addresses_from_file){
        alias_tests.push_back(test_addresses);
    }

    for (const auto & alias_set : alias_tests){

        char separator = '_';

        // Direct UDP
        std::vector <Tins::IP> direct_udp_probes;

        // Direct ICMP
        std::vector <Tins::IP> direct_icmp_probes;

        // Indirect UDP
        std::unordered_map<Tins::IPv4Address, Tins::IP> indirect_udp_probes;

        std::cout << "Starting to evaluate rate limiting for:" << to_string(alias_set) << "\n";
        for (const auto & icmp_triggering_triplet : alias_set) {

            // Add the direct UDP probe
            direct_udp_probes.push_back(icmp_triggering_triplet.get_icmp_dst_unreachable());

            // Add the direct ICMP probe
            direct_icmp_probes.push_back(icmp_triggering_triplet.get_icmp_echo_reply());

            // Add the indirect UDP probe
            indirect_udp_probes.insert(std::make_pair(icmp_triggering_triplet.test_address(),
                                                                 icmp_triggering_triplet.get_icmp_ttl_exceeded()));
        }

        for(int i = 1; pow(2, i) < max_probing_rate; ++i){
            // Probing rate represents the number of packets to send in 1 sec
            auto probing_rate = static_cast<int>(pow(2, i));
            auto nb_probes = 5 * probing_rate;

            rate_limit_test_t udp_direct_test(nb_probes, probing_rate, sniff_interface,
                                              direct_udp_probes);
            udp_direct_test.set_pcap_file(build_pcap_name(output_dir, "icmp_unreachable", to_file_name(alias_set, separator), probing_rate));

            std::cout << "UDP direct probing for " << to_string(alias_set) << " with probing rate " << probing_rate <<  "...\n";
            udp_direct_test.start();

            std::this_thread::sleep_for(std::chrono::seconds(2));


            // ICMP direct test
            rate_limit_test_t icmp_direct_test(nb_probes, probing_rate, sniff_interface, direct_icmp_probes);


            icmp_direct_test.set_pcap_file(build_pcap_name(output_dir, "icmp_echo_reply", to_file_name(alias_set, separator), probing_rate));

            std::cout << "ICMP direct probing for " << to_string(alias_set) <<  " with probing rate " << probing_rate <<"...\n";
            icmp_direct_test.start();

            std::this_thread::sleep_for(std::chrono::seconds(2));


            // Indirect UDP test

            rate_limit_test_t udp_indirect_test(nb_probes, probing_rate, sniff_interface, indirect_udp_probes);

            udp_indirect_test.set_pcap_file(build_pcap_name(output_dir, "icmp_ttl_exceeded", to_file_name(alias_set, separator), probing_rate));
            std::cout << "UDP indirect probing for " << to_string(alias_set) << " with probing rate " << probing_rate << "...\n";

            udp_indirect_test.start();
            std::this_thread::sleep_for(std::chrono::seconds(2));

        }
    }

    return 0;
}



