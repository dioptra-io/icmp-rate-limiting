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
#include "sender_t.hpp"
#include "include/rate_limit_test_t.hpp"
using namespace Tins;

int buffer_size(int socket_fd, int buffer_type){
    int res = 0;

    socklen_t optlen;
    int sendbuff;
    // Get buffer size
    optlen = sizeof(sendbuff);
    res = getsockopt(socket_fd, SOL_SOCKET, buffer_type, &sendbuff, &optlen);

    if(res == -1){
        fprintf(stderr, "Error getsockopt one");
        return -1;
    }
    else{
        fprintf(stderr, "send buffer size = %d\n", sendbuff);
        return sendbuff;
    }
}

int open_L3_socket(int family, int type, int protocol){
    int socket_fd;
    // Open 2 sockets, one for each alias candidates
    if ((socket_fd = socket(family, type, protocol)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int sendbuff = buffer_size(socket_fd, SO_SNDBUF);

    sendbuff *= 64;
    int res = setsockopt(socket_fd, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff));

    if(res == -1){
        perror("setsockopt");
        exit(errno);
    }

    sendbuff = buffer_size(socket_fd, SO_SNDBUF);
    const int on = 1;
    #ifndef _WIN32
        typedef const void* option_ptr;
    #else
        typedef const char* option_ptr;
    #endif
    if (setsockopt(socket_fd, IP_PROTO_IP, IP_HDRINCL, (option_ptr)&on, sizeof(on)) != 0) {
        perror("setsockopt");
        exit(errno);
    }

    return socket_fd;
}

sockaddr_in get_sockaddr_in(uint32_t dst_ip){
    sockaddr_in link_addr;
    link_addr.sin_family = AF_INET;
    link_addr.sin_port = 0;
    link_addr.sin_addr.s_addr = dst_ip;

    return link_addr;
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
    IPv4Address after_address;


    while ((c = getopt (argc, argv, "a:b:")) != -1)
        switch (c)
        {
            case 'a':
                after_address = IPv4Address{optarg};
                break;
            case 'b':
                before_address = IPv4Address{optarg};
                break;
            case '?':
                if (optopt == 'a' or optopt == 'b')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr,
                             "Unknown option character `\\x%x'.\n",
                             optopt);
                return 1;
            default:
                abort ();
        }




    // Probing rate for before and after interfaces (if set)

    // The testing suite consist in 3 tests, 1 per ICMP message type that can be rate-limited: Indirect (TTL-Exceeded) messages and Direct probing (Destination Unreachable or Echo reply)
    PacketSender sender;

    // Progressively increase the sending rate (log scale)
    auto max_probing_rate = 10000;

    for(int i = 1000; i < max_probing_rate; i *= 10){
        auto rates = {1, 5};
        for (const auto j : rates){
            // Probing rate represents the number of packets to send in 1 sec
            auto probing_rate = j * i;
            auto nb_probes = 5 * probing_rate;

//    // UDP direct, put a very high dst port.
//    rate_limit_test_t<UDP> udp_direct_test(nb_probes, probing_rate, sniff_interface, destination_alias1, destination_alias2, default_sport, default_dport);
//    udp_direct_test.set_pcap_file("resources/icmp_dst_unreachable.pcap");
//    //udp_direct_test.set_before_address(default_sport, default_dport, "4.69.111.194");
//    udp_direct_test.start(sender);
//
//    std::this_thread::sleep_for(std::chrono::seconds(2));
//
            // ICMP direct
            rate_limit_test_t<ICMP> icmp_direct_test(nb_probes, probing_rate, sniff_interface, destination_alias1, destination_alias2);
            icmp_direct_test.set_pcap_file("resources/icmp_echo_reply.pcap");
            if (before_address != IPv4Address()){
                icmp_direct_test.set_before_address(before_address);
            }
            icmp_direct_test.start(sender);

            std::this_thread::sleep_for(std::chrono::seconds(2));

            // Inverse ICMP direct
            rate_limit_test_t<ICMP> icmp_direct_test_reverse(nb_probes, probing_rate, sniff_interface, destination_alias2, destination_alias1);
            icmp_direct_test_reverse.set_pcap_file("resources/icmp_echo_reply.pcap");
            if (before_address != IPv4Address()){
                icmp_direct_test_reverse.set_before_address(before_address);
            }
            icmp_direct_test_reverse.start(sender);

            std::this_thread::sleep_for(std::chrono::seconds(2));


            // UDP direct
//            rate_limit_test_t<UDP> udp_direct_test(nb_probes, probing_rate, sniff_interface, destination_alias1, destination_alias2, default_sport, default_dport);
//            udp_direct_test.set_pcap_file("resources/icmp_host_unreachable.pcap");
//            udp_direct_test.set_before_address(default_sport, default_dport, before_address);
//            udp_direct_test.start(sender);
//
//            std::this_thread::sleep_for(std::chrono::seconds(2));
//
//            rate_limit_test_t<UDP> udp_direct_test_reverse(nb_probes, probing_rate, sniff_interface, destination_alias2, destination_alias1, default_sport, default_dport);
//            udp_direct_test_reverse.set_pcap_file("resources/icmp_host_unreachable.pcap");
//            udp_direct_test_reverse.set_before_address(default_sport, default_dport, before_address);
//            udp_direct_test_reverse.start(sender);
//            // UDP indirect
//            rate_limit_test_t<UDP> udp_indirect_test(nb_probes, probing_rate, sniff_interface, destination, destination_alias1, destination_alias2, ttl, udp_sport1, udp_sport2, default_dport);
//            udp_indirect_test.set_pcap_file("resources/icmp_ttl_exceeded.pcap");
//            udp_indirect_test.set_before_address(24001, 33345, 8, "195.12.233.115", "213.155.141.226");
//////    udp_indirect_test.set_after_address(24033, 33345, 13, "195.12.233.115", "213.248.79.106");
//            udp_indirect_test.start(sender);
        }
    }




    return 0;
}