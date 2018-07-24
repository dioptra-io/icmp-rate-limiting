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

#include <boost/filesystem.hpp>

#include "include/utils/file_utils_t.hpp"
#include "include/utils/tins_utils_t.hpp"
#include "include/sender_t.hpp"
#include "include/rate_limit_test_t.hpp"
using namespace Tins;

using namespace utils;

using namespace boost::filesystem;
namespace {
    std::string build_pcap_name(std::string folder, std::string icmp_type, std::string destination, int rate){
        std::stringstream pcap_file_stream;
        pcap_file_stream << folder << icmp_type << "_" << destination << "_" << rate << ".pcap";
        return pcap_file_stream.str();
    }

    struct icmp_trigger_probes_t{
        IP icmp_ttl_exceeded;
        IP icmp_dst_unreachable;
        IP icmp_echo_reply;
    };


    bool operator == (const icmp_trigger_probes_t & triplet1, const icmp_trigger_probes_t & triplet2 ){
        return triplet1.icmp_echo_reply.dst_addr() == triplet2.icmp_echo_reply.dst_addr();
    }
    enum class icmp_messages_t{
        ICMP_TTL_EXCEEDED = ICMP::Flags::TIME_EXCEEDED,
        ICMP_DST_UNREACHABLE = ICMP::Flags::DEST_UNREACHABLE,
        ICMP_ECHO_REPLY = ICMP::Flags::ECHO_REPLY
    };

    uint8_t  test_ttl = 7;

    IP build_icmp_triggering_probe(const IPv4Address & dst_ip, const IPv4Address & src_ip,  uint16_t sport, uint16_t dport, uint8_t ttl, ICMP::Flags icmp_type){
        IP icmp_triggering_probe;
        if (icmp_type == ICMP::TIME_EXCEEDED or icmp_type == ICMP::DEST_UNREACHABLE){
            icmp_triggering_probe = IP(dst_ip, src_ip)/UDP(dport, sport);
        } else if (icmp_type == ICMP::ECHO_REPLY){
            icmp_triggering_probe = IP(dst_ip, src_ip) / ICMP();
        }
        if (icmp_type == ICMP::TIME_EXCEEDED){
            icmp_triggering_probe.ttl(ttl);
        } else {
            icmp_triggering_probe.ttl(64);
        }
        return icmp_triggering_probe;
    }

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

        auto icmp_triggering_probe = build_icmp_triggering_probe(dst_ip, src_ip, 24000, 34345, test_ttl, icmp_type);


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
    bool is_addresses_from_file = true;

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
                    auto ttl_exceeded_probe = build_icmp_triggering_probe(address, sniff_interface.ipv4_address(), 24000, 34345, test_ttl, ICMP::TIME_EXCEEDED);
                    auto dst_unreachable_probe = build_icmp_triggering_probe(target_ip, sniff_interface.ipv4_address(),  24000, 34345, 0, ICMP::DEST_UNREACHABLE);
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

    if (is_addresses_from_file){
        path address_dir("resources/");
        auto ip_addresses_str = extract_ips_from_filenames(address_dir);
        for (const auto & ip_address_str : ip_addresses_str){
            // Find the corresponding pcap files 2.

            // First ttl-exceeded file
            std::stringstream ttl_exceeded_file;
            ttl_exceeded_file << "icmp_ttl_exceeded_" << ip_address_str << "_2.pcap";

            auto ttl_exceeded_probes = retrieve_matchers(ttl_exceeded_file.str());
            IP ttl_exceeded_probe = ttl_exceeded_probes.at(ip_address_str);

            // Second echo-reply file
            std::stringstream echo_reply_file;
            echo_reply_file << "icmp_echo_reply"

            // Third destination unreachable file


        }
    }


    for (const auto & icmp_triggering_triplet : test_addresses){

        std::cout << "Starting to evaluate rate limiting for:" << icmp_triggering_triplet.icmp_dst_unreachable.dst_addr().to_string() << "\n";

        for(int i = 1; pow(2, i) < max_probing_rate; ++i){
            // Probing rate represents the number of packets to send in 1 sec
            auto probing_rate = static_cast<int>(pow(2, i));
            auto nb_probes = 3 * probing_rate;

            // UDP direct, put a very high dst port.
            std::vector <Tins::IP> direct_udp_candidates_probes;
            direct_udp_candidates_probes.push_back(icmp_triggering_triplet.icmp_dst_unreachable);
            std::vector <Tins::IP> direct_udp_candidates_probes_options;
//            if (before_address != IPv4Address()){
//                auto probe_dst_option_before = IP(before_address)/UDP(default_dport, default_sport);
//                direct_udp_candidates_probes_options.push_back(probe_dst_option_before);
//            }
            rate_limit_test_t udp_direct_test(nb_probes, probing_rate, sniff_interface,
                                              direct_udp_candidates_probes, direct_udp_candidates_probes_options);
            udp_direct_test.set_pcap_file(build_pcap_name("resources/", "icmp_unreachable", icmp_triggering_triplet.icmp_dst_unreachable.dst_addr().to_string(), probing_rate));
            //udp_direct_test.set_before_address(default_sport, default_dport, "4.69.111.194");

            std::cout << "UDP direct probing for " << icmp_triggering_triplet.icmp_dst_unreachable.dst_addr().to_string() << " with probing rate " << probing_rate <<  "...\n";
            udp_direct_test.start();

            std::this_thread::sleep_for(std::chrono::seconds(2));


            // ICMP direct
            std::vector <Tins::IP> direct_icmp_candidates_probes;
            direct_icmp_candidates_probes.push_back(icmp_triggering_triplet.icmp_echo_reply);
            std::vector <Tins::IP> direct_icmp_candidates_probes_options;
//            if (before_address != IPv4Address()){
//                auto probe_dst_option_before = IP(before_address)/ICMP();
//                direct_icmp_candidates_probes_options.push_back(probe_dst_option_before);
//            }
            rate_limit_test_t icmp_direct_test(nb_probes, probing_rate, sniff_interface, direct_icmp_candidates_probes, direct_icmp_candidates_probes_options);


            icmp_direct_test.set_pcap_file(build_pcap_name("resources/", "icmp_echo_reply", icmp_triggering_triplet.icmp_echo_reply.dst_addr().to_string(), probing_rate));

            std::cout << "ICMP direct probing for " << icmp_triggering_triplet.icmp_dst_unreachable.dst_addr().to_string() <<  " with probing rate " << probing_rate <<"...\n";
            icmp_direct_test.start();

            std::this_thread::sleep_for(std::chrono::seconds(2));


            // Indirect UDP test
            std::unordered_map<Tins::IPv4Address, Tins::IP> indirect_udp_candidates_probes;
            indirect_udp_candidates_probes.insert(std::make_pair(icmp_triggering_triplet.icmp_echo_reply.dst_addr(), icmp_triggering_triplet.icmp_ttl_exceeded));
            std::unordered_map<Tins::IPv4Address, Tins::IP> indirect_udp_candidates_probes_options;

            rate_limit_test_t udp_indirect_test(nb_probes, probing_rate, sniff_interface, indirect_udp_candidates_probes, indirect_udp_candidates_probes_options);

            udp_indirect_test.set_pcap_file(build_pcap_name("resources/", "icmp_ttl_exceeded", icmp_triggering_triplet.icmp_echo_reply.dst_addr().to_string(), probing_rate));
            std::cout << "UDP indirect probing for " << icmp_triggering_triplet.icmp_dst_unreachable.dst_addr().to_string() << " with probing rate " << probing_rate << "...\n";

            udp_indirect_test.start();
            std::this_thread::sleep_for(std::chrono::seconds(2));


        }


    }




    return 0;
}