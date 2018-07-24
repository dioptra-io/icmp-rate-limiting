//
// Created by System Administrator on 28/06/2018.
//

#ifndef ICMPRATELIMITING_SENDER_T_HPP
#define ICMPRATELIMITING_SENDER_T_HPP

#include <vector>
#include <tins/tins.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <dnet.h>
class sender_t{
public:

    sender_t(int family, int type, int protocol);

    void send(Tins::PDU& pdu);

    int set_buffer_size(int buffer_size);
    int get_buffer_size(int buffer_type);

    sockaddr_in get_sockaddr_in(uint32_t dst_ip){
        sockaddr_in link_addr;
        link_addr.sin_family = AF_INET;
        link_addr.sin_port = 0;
        link_addr.sin_addr.s_addr = dst_ip;

        return link_addr;
    }
    ~sender_t();


private:


    int open_L3_socket(int family, int type, int protocol);
    void send_l3_socket(int socket, Tins::PDU& pdu, struct sockaddr* link_addr, uint32_t len_addr);

    int socket_fd;
};


#endif //ICMPRATELIMITING_SENDER_T_HPP
