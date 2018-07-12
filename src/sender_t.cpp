//
// Created by System Administrator on 28/06/2018.
//

#include <sys/socket.h>
#include <netinet/in.h>
#include <cerrno>
#include <dnet.h>

#include "../include/sender_t.hpp"


using namespace Tins;

void sender_t::send_l3_socket(int socket, PDU &pdu, struct sockaddr *link_addr, uint32_t len_addr) {
    PDU::serialization_type buffer = pdu.serialize();
    const int buf_size = static_cast<int>(buffer.size());
    if (sendto(socket, (const char*)&buffer[0], buf_size, 0, link_addr, len_addr) < 0) {
        perror("sendto()");
        exit(errno);
    }
}

int sender_t::open_L3_socket(int family, int type, int protocol) {
    int socket_fd;
    // Open 2 sockets, one for each alias candidates
    if ((socket_fd = socket(family, type, protocol)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    return socket_fd;

}

int sender_t::get_buffer_size(int buffer_type) {
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

int sender_t::set_buffer_size(int buffer_size) {

    auto sendbuff = buffer_size;
    int res = setsockopt(socket_fd, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff));

    if(res == -1){
        perror("setsockopt");
        exit(errno);
    }

    sendbuff = get_buffer_size(SO_SNDBUF);
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

sender_t::sender_t(int family, int type, int protocol) :
    socket_fd(open_L3_socket(family, type, protocol))
{

}

void sender_t::send(Tins::PDU &pdu) {
    auto ip = pdu.rfind_pdu<IP>();
    auto link_addr = get_sockaddr_in(ip.dst_addr());
    send_l3_socket(socket_fd, pdu, (struct sockaddr*)&link_addr, sizeof(link_addr));
}


