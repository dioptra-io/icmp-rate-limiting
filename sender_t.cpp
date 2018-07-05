//
// Created by System Administrator on 28/06/2018.
//

#include "sender_t.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <cerrno>

using namespace Tins;

void sender_t::send_l3_socket(int socket, PDU &pdu, struct sockaddr *link_addr, uint32_t len_addr) {
    PDU::serialization_type buffer = pdu.serialize();
    const int buf_size = static_cast<int>(buffer.size());
    if (sendto(socket, (const char*)&buffer[0], buf_size, 0, link_addr, len_addr) < 0) {
        perror("sendto()");
        exit(errno);
    }
}
