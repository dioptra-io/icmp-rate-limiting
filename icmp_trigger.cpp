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
#include "include/sender_t.hpp"
#include "include/rate_limit_test_t.hpp"
using namespace Tins;

namespace {
    std::string build_pcap_name(std::string folder, std::string icmp_type, std::string destination, int rate){
        std::stringstream pcap_file_stream;
        pcap_file_stream << folder << icmp_type << "_" << destination << "_" << rate << ".pcap";
        return pcap_file_stream.str();
    }

    struct icmp_trigger_probes{
        IP icmp_ttl_exceeded;
        IP icmp_dst_unreachable;
        IP icmp_echo_reply;
    };

    enum class icmp_messages_t{
        ICMP_TTL_EXCEEDED, ICMP_DST_UNREACHABLE, ICMP_ECHO_REPLY
    };

    uint8_t  test_ttl = 6;

    IP build_icmp_triggering_probe(const IPv4Address & dst_ip, uint16_t sport, uint16_t dport, uint8_t ttl, icmp_messages_t icmp_type){
        IP icmp_triggering_probe;
        if (icmp_type==icmp_messages_t::ICMP_TTL_EXCEEDED or icmp_type == icmp_messages_t::ICMP_DST_UNREACHABLE){
            icmp_triggering_probe = IP(dst_ip)/UDP(dport, sport);
        } else if (icmp_type == icmp_messages_t::ICMP_ECHO_REPLY){
            icmp_triggering_probe = IP(dst_ip) / ICMP();
        }
        if (icmp_type == icmp_messages_t::ICMP_TTL_EXCEEDED){
            icmp_triggering_probe.ttl(ttl);
        } else {
            icmp_triggering_probe.ttl(64);
        }
        return icmp_triggering_probe;
    }

    std::pair<bool, IPv4Address> is_responsive(const IPv4Address & dst_ip, icmp_messages_t icmp_type){
        PacketSender test_sender;
        SnifferConfiguration configuration;
        configuration.set_immediate_mode(true);
        configuration.set_filter("ip proto \\icmp");
        Sniffer sniffer("en7", configuration);


        // Start sniffing

        std::vector<Packet> sniffed_packets;

        auto handler = [&sniffed_packets](Packet & packet){
            sniffed_packets.push_back(packet);
            return false;
        };

        std::thread sniff_thread(
                [&]() {
                    sniffer.sniff_loop(handler);
                }
        );

        // Find the TTL-Exceeding message at TTL 6

        auto icmp_triggering_probe = build_icmp_triggering_probe(dst_ip, 24000, 34345, test_ttl, icmp_type);

        try{
            test_sender.send(icmp_triggering_probe);
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            sniff_thread.detach();
            if (!sniffed_packets.empty()) {
                auto icmp_ttl_exceeded_response = sniffed_packets[0].pdu()->find_pdu<IP>();
                if (icmp_ttl_exceeded_response != nullptr) {
                    auto response_ip = icmp_ttl_exceeded_response->src_addr();
                    return std::make_pair(true, response_ip);
                }
            }
        }
        // In case of random address which is bad
        catch (const socket_write_error & e ){
            std::cerr << e.what() << "\n";
        }
        return std::make_pair(false, IPv4Address());
    }

}

int main(int argc, char ** argv) {

    if (argc < 1){
        fprintf(stderr, "Usage: <destination> <candidates> <ports> <ttl> <options>");
    }
    auto destination = argv[1];
    auto destination_alias1 = argv[2];
    auto destination_alias2 = argv[3];
    uint16_t default_sport = 24000;
    uint16_t default_dport = 33435;
    uint16_t udp_sport1 = 0;
    uint16_t udp_sport2 = 0;
    uint16_t tcp_sport1 = 0;
    uint16_t tcp_sport2 = 0;
    uint8_t  ttl = 0;
    if (argc > 3){
        udp_sport1 = std::atoi(argv[4]);
        udp_sport2 = std::atoi(argv[5]);
        tcp_sport1 = std::atoi(argv[4]);
        tcp_sport2 = std::atoi(argv[5]);
        ttl = std::atoi(argv[6]);
    }

    auto sniff_interface = NetworkInterface::default_interface();
    // Parse options
    int c;
    IPv4Address before_address {"212.73.200.45"};


    // Probing rate for before and after interfaces (if set)

    // The testing suite consist in 3 tests, 1 per ICMP message type that can be rate-limited: Indirect (TTL-Exceeded) messages and Direct probing (Destination Unreachable or Echo reply)

    // Progressively increase the sending rate (log scale)
    auto max_probing_rate = 10000;


    uint8_t test_ttl = 6;

    // Find 1000 random addresses from traceroute TTL-exceeded

    std::vector<icmp_trigger_probes> test_addresses;
    while (test_addresses.size() < 100){
        // Generate a random address
        std::vector<int> bytes(4, 0);
        std::stringstream address_stream;
        for (int i = 0; i < bytes.size(); ++i) {
            bytes[i] = std::rand() % 255;
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

        auto is_ttl_exceeded_responsive = is_responsive(address, icmp_messages_t::ICMP_TTL_EXCEEDED);
        if (is_ttl_exceeded_responsive.first){
            auto target_ip = is_ttl_exceeded_responsive.second;
            auto is_traceroutable = is_responsive(target_ip, icmp_messages_t::ICMP_DST_UNREACHABLE);
            auto is_pingable = is_responsive(target_ip, icmp_messages_t::ICMP_ECHO_REPLY);

            if (is_pingable.first or is_traceroutable.first){
                auto ttl_exceeded_probe = build_icmp_triggering_probe(address, 24000, 34345, test_ttl, icmp_messages_t::ICMP_TTL_EXCEEDED);
                auto dst_unreachable_probe = build_icmp_triggering_probe(target_ip, 24000, 34345, 0, icmp_messages_t::ICMP_DST_UNREACHABLE);
                auto echo_reply_probe = build_icmp_triggering_probe(target_ip, 0, 0, 0, icmp_messages_t::ICMP_ECHO_REPLY);
                test_addresses.push_back({ttl_exceeded_probe, dst_unreachable_probe, echo_reply_probe});
            }
        }

        if (test_addresses.size() %10 == 0){
            std::cout << "Found " << test_addresses.size() << " addresses to test on 100 expected." << "\n";
        }
//

    }


    for (const auto & icmp_triggering_triplet : test_addresses){

        std::cout << "Starting to evaluate rate limiting for:" << icmp_triggering_triplet.icmp_dst_unreachable.dst_addr().to_string() << "\n";

        for(int i = 0; pow(2, i) < max_probing_rate; ++i){
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

            std::cout << "UDP direct probing..." << "\n";
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

            std::cout << "ICMP direct probing..." << "\n";
            icmp_direct_test.start();

            std::this_thread::sleep_for(std::chrono::seconds(2));


            // Indirect UDP test
            std::vector <Tins::IP> indirect_udp_candidates_probes;
            indirect_udp_candidates_probes.push_back(icmp_triggering_triplet.icmp_ttl_exceeded);
            std::vector<Tins::IP> indirect_udp_candidates_probes_options;
            rate_limit_test_t udp_indirect_test(nb_probes, probing_rate, sniff_interface, indirect_udp_candidates_probes, indirect_udp_candidates_probes_options);

            udp_indirect_test.set_pcap_file(build_pcap_name("resources/", "icmp_ttl_exceeded", icmp_triggering_triplet.icmp_echo_reply.dst_addr().to_string(), probing_rate));
            std::cout << "UDP indirect probing..." << "\n";

            udp_indirect_test.start();
            std::this_thread::sleep_for(std::chrono::seconds(2));


        }


    }




    return 0;
}