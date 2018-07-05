//
// Created by System Administrator on 28/06/2018.
//

#ifndef ICMPRATELIMITING_SENDER_T_HPP
#define ICMPRATELIMITING_SENDER_T_HPP

#include <vector>
#include <tins/tins.h>

class sender_t{
public:
    void send_l3_socket(int socket, Tins::PDU& pdu, struct sockaddr* link_addr, uint32_t len_addr);
};


#endif //ICMPRATELIMITING_SENDER_T_HPP
