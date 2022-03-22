#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include "include/color.hpp"

const int SERVERNAME_MAXLEN = 64;

class Client_Socket{
    private:
        int _protocol;
        std::string _server;
        std::string _IP;
        struct addrinfo hints;
        struct addrinfo *serverinfo;
        int _server_socket_file_descriptor; 

    public:
        Client_Socket() = delete;
        Client_Socket(const char *ip, std::string server, int protocol);
        virtual ~Client_Socket();
        Client_Socket(const Client_Socket&) = delete;
        Client_Socket(Client_Socket&&) = delete;

        int createSocket();
        int connectSocket();

        template<typename T> int Send(int Socket_FD_num, const T &data);
        int Receive(int Socket_FD_num, void *data, size_t len);

};

Client_Socket::Client_Socket(const char *serverIP, std::string server, int protocol){
    _IP = serverIP ? serverIP : "";
    _server = server;
    _protocol = protocol;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = _protocol;

    try{
        int status = getaddrinfo(_IP.c_str(), _server.c_str(), &hints, &serverinfo);
        if(status != 0) throw(gai_strerror(status));
    }
    catch(const char *err){
        std::cerr << err << std::endl;
        exit(-1);
    }
    std::cout << "Construct client socket successfully!" << std::endl;
}

Client_Socket::~Client_Socket(){
    freeaddrinfo(serverinfo);
    try{
        int status = close(_server_socket_file_descriptor);
        if(status == -1) throw("close error when destruct server socket!");
    }
    catch(const char *err){
        std::cerr << FRONT_RED << err << RESET_COLOR << std::endl;
        printf("-Error NO.%d: %s\n", errno, strerror(errno));
        return;
    }
    std::cout << "Destruct client socket successfully!" << std::endl;
}

int Client_Socket::createSocket(){
    try{
        _server_socket_file_descriptor = socket(serverinfo->ai_family, serverinfo->ai_socktype, serverinfo->ai_protocol);
        if(_server_socket_file_descriptor == -1) throw("create socket error!");
    }
    catch(const char *err){
        std::cerr << FRONT_RED << err << RESET_COLOR << std::endl;
        printf("-Error NO.%d: %s\n", errno, strerror(errno));
        return errno;
    }
    std::cout << FRONT_GREEN << "create socket successfully!" << RESET_COLOR << std::endl;
    return 0;
}

int Client_Socket::connectSocket(){
    try{
        int status = connect(_server_socket_file_descriptor, serverinfo->ai_addr, serverinfo->ai_addrlen);
        if(status == -1) throw("connect error!");
    }
    catch(const char *err){
        std::cerr << FRONT_RED << err << RESET_COLOR << std::endl;
        printf("-Error NO.%d: %s\n", errno, strerror(errno));
        return errno;
    }
    char hostName[SERVERNAME_MAXLEN] = {0};
    Receive(_server_socket_file_descriptor, hostName, SERVERNAME_MAXLEN);
    std::cout << "server name: " << BOLD << hostName << RESET_COLOR << std::endl;
    std::cout << FRONT_GREEN << "connect successfully!" << RESET_COLOR << std::endl;
    return 0;
}

template<typename T>
int Client_Socket::Send(int Socket_FD_num, const T &data){
    // TODO
    return 0;
}

int Client_Socket::Receive(int Socket_FD_num, void *data, size_t len){
    int status = 0;
    try{
        status = recv(_server_socket_file_descriptor, data, len, 0);
        if(status == -1) throw("tcp receive error!");
    }
    catch(const char *err){
        std::cerr << FRONT_RED << err << RESET_COLOR << std::endl;
        printf("-Error NO.%d: %s\n", errno, strerror(errno));
        return errno;
    }
    catch(const std::out_of_range &err){
        std::cerr << FRONT_RED << err.what() << std::endl;
        return -1;
    }
    std::cout << FRONT_BLUE << "---> " << RESET_COLOR << (char*)data << std::endl;
    if(status == 0){
        std::cout << FRONT_YELLOW 
            << "receive 0 byte data, the remote side may close the connection..." 
            << RESET_COLOR << std::endl;
    }
    return 0;
}

int main(){
    Client_Socket ttt("localhost", "10001", SOCK_STREAM);
    ttt.createSocket();
    ttt.connectSocket();
    return 0;
}