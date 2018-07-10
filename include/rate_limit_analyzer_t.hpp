//
// Created by System Administrator on 05/07/2018.
//

#ifndef ICMPRATELIMITING_RATE_LIMIT_ANALYZER_HPP
#define ICMPRATELIMITING_RATE_LIMIT_ANALYZER_HPP

#include <tuple>
#include <unordered_map>
#include <tins/tins.h>

class rate_limit_analyzer_t {

public:

    enum class probing_style_t{
        DIRECT, INDIRECT
    };

    using intervals_t = std::tuple<bool, double, double>;
    // Direct probing constructor
    rate_limit_analyzer_t();

    using port_ttl_ip_t = std::tuple<uint16_t, uint8_t, Tins::IPv4Address>;
    // Indirect probing constructor with port and expected interface
    rate_limit_analyzer_t(const port_ttl_ip_t &, const port_ttl_ip_t &);
    using responsive_info_probe_t = std::pair<bool, Tins::Packet>;
    using responsiveness_t = std::unordered_map<Tins::IPv4Address, std::vector<responsive_info_probe_t>>;

    template<typename Protocol>
    void start(const std::string &pcap_file) {

        auto build_series = [this](Tins::Packet & packet){
            auto pdu = packet.pdu();
            auto icmp = pdu->find_pdu<Tins::ICMP>();
            if (icmp == NULL or icmp->type() == Tins::ICMP::Flags::ECHO_REQUEST){
                outgoing_packets.push_back(packet);
            } else {
                icmp_replies.push_back(packet);
            }
            return true;
        };

        Tins::FileSniffer sniffer(pcap_file);
        sniffer.sniff_loop(build_series);
        // Matches probe with replies and extract responsiveness
        sort_by_timestamp(outgoing_packets);
        // Remove the last packet that had been sent to shut the sniffer.
        outgoing_packets.erase(outgoing_packets.end()-1);
        for(const auto & packet : outgoing_packets){
            auto outgoing_pdu = packet.pdu();
            // Find the IP layer
            auto ip = outgoing_pdu->rfind_pdu<Tins::IP>();
            auto transport = ip.find_pdu<Protocol>();
            if (transport == nullptr){
                continue;
            }

            auto it = std::find_if(icmp_replies.begin(), icmp_replies.end(), [&ip, &transport](const Tins::Packet & matching_packet){
                auto pdu = matching_packet.pdu();
                auto icmp = pdu->find_pdu<Tins::ICMP>();
                if (icmp->type() == Tins::ICMP::Flags::ECHO_REPLY){
                    if constexpr (std::is_same<Protocol, Tins::ICMP>::value){
                        try{
                            if (icmp->id() == transport->id()){
                                return true;
                            }
                        } catch (const Tins::malformed_packet & e){
                            std::cerr << e.what() << "\n";
                        }
                    }
                    // We are in an ICMP direct probing so we match se probes with the icmp id

                } else {
                    // We are in a TCP or UDP probing so match with the probes with the ip id
                    try{
                        const auto &raw_inner_transport = icmp->rfind_pdu<Tins::RawPDU>();
                        auto inner_ip = raw_inner_transport.to<Tins::IP>();
                        if (inner_ip.id() == ip.id()){
                            return true;
                        }
                    } catch (const Tins::malformed_packet & e){
                        std::cerr << e.what() << "\n";
                    }
                }
                return false;
            });
            if (it != icmp_replies.end()){
                auto ip_reply = it->pdu()->template rfind_pdu<Tins::IP>().src_addr();
                // Erase this response.

//                std::cout << "Responsive " << ip_reply << " " <<  std::chrono::microseconds(packet.timestamp()).count() << "\n";
                // Insert the reply in the responsiveness map
                auto ip_key = packets_per_interface.find(ip_reply);
                if (ip_key == packets_per_interface.end()) {
                    packets_per_interface.insert(std::make_pair(ip_reply, std::vector<responsive_info_probe_t>()));
                }
                packets_per_interface[ip_reply].push_back(std::make_pair(true, *it));

                icmp_replies.erase(it);
            } else {
                Tins::IPv4Address dst_ip;
                if (probing_style == probing_style_t::DIRECT){
                    // Match the ip probe with the destination in case of direct probing
                    dst_ip = ip.dst_addr();
                } else {
                    if constexpr(std::is_same<Protocol, Tins::UDP>::value or std::is_same<Protocol, Tins::TCP>::value){
                        // Match the ip probe with the sport in case of indirect probing
                        if (match_probe<Protocol>(port_ttl_ip1, ip, transport)){
                            dst_ip = std::get<2>(port_ttl_ip1);
                        } else if (match_probe<Protocol>(port_ttl_ip2, ip, transport)){
                            dst_ip = std::get<2>(port_ttl_ip2);
                        } else if (match_probe<Protocol>(port_ttl_ip_before, ip, transport)){
                            dst_ip = std::get<2>(port_ttl_ip_before);
                        } else if (match_probe<Protocol>(port_ttl_ip_after, ip, transport)){
                            dst_ip = std::get<2>(port_ttl_ip_after);
                        }
                    }
                }

                auto ip_key = packets_per_interface.find(dst_ip);
                if (ip_key == packets_per_interface.end()){
                    packets_per_interface.insert(std::make_pair(dst_ip, std::vector<responsive_info_probe_t>()));
                }
                packets_per_interface[dst_ip].push_back(std::make_pair(false, packet));
//                std::cout << "Unresponsive " << dst_ip << " " <<  std::chrono::microseconds(packet.timestamp()).count() << "\n";


            }
        }
    }

    using time_interval_t = std::pair<double,double>;
    using responsiveness_time_interval_t = std::tuple<bool, int, time_interval_t >;
    using time_series_t = std::vector<responsiveness_time_interval_t>;

    std::unordered_map<Tins::IPv4Address, time_series_t> extract_responsiveness_time_series();

    double

    void dump_loss_rate();
    void dump_time_series();
    void set_port_ttl_ip_before(const port_ttl_ip_t & new_port_ttl_ip_before);
    void set_port_ttl_ip_after(const port_ttl_ip_t & new_port_ttl_ip_after);

    std::unordered_map<Tins::IPv4Address, double> compute_loss_rate();


private:


    // Private functions to compute statistics indicators.
    double compute_loss_rate(const std::vector<responsive_info_probe_t> &);
    time_series_t extract_responsiveness_time_series(const std::vector <responsive_info_probe_t> &);


    template<typename Protocol>
    bool match_probe(const port_ttl_ip_t & candidate, const Tins::IP & probe, Protocol* transport){
        auto sport = transport->sport();
        auto ttl = probe.ttl();
        return sport == std::get<0>(candidate) and ttl == std::get<1>(candidate);
    }

    void sort_by_timestamp(std::vector<Tins::Packet> &packets);
//    std::vector<intervals_t> compute_responsiveness();
    // Analysis
    probing_style_t probing_style;

    port_ttl_ip_t port_ttl_ip1;
    port_ttl_ip_t port_ttl_ip2;
    port_ttl_ip_t port_ttl_ip_before;
    port_ttl_ip_t port_ttl_ip_after;

    responsiveness_t packets_per_interface;
    std::vector<Tins::Packet> outgoing_packets;
    std::vector<Tins::Packet> icmp_replies;


};


#endif //ICMPRATELIMITING_RATE_LIMIT_ANALYZER_HPP
