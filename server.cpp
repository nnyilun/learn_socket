#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <cstdio>
#include <vector>
#include <map>
#include <mutex>
#include <memory>
#include <thread>
// #include <exception>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
// #include <sys/wait.h>
#include <arpa/inet.h>
// #include <netinet/in.h>
// #include <csignal>
#include <cerrno>
#include <unistd.h>
#include <netdb.h>
#include "include/color.hpp"

const int HOSTNAME_MAXLEN = 64;

class Server_Socket{
    private:
        int _protocol;
        int _connections;
        std::string _server;
        std::string _IP;
        struct addrinfo hints;
        struct addrinfo *serverinfo;
        int _server_socket_file_descriptor; 
        char hostName[HOSTNAME_MAXLEN];
        std::vector<int> connected_client_file_descriptor;
        std::mutex FD_mutex;
        std::map<int, std::pair<std::thread, int>> thread_session;
        class Session{
            private:
                int chatroom_owner_FD;
                std::vector<int> client_FD;
            
            public:
                Session() = delete;
                Session(int owner_FD);
                virtual ~Session();
                Session(const Session&) = delete;
                Session(Session&&) = delete;

                int run();
        };

    public:
        Server_Socket() = delete;
        Server_Socket(const char *ip, std::string server, int protocol, int connections=64);
        virtual ~Server_Socket();
        Server_Socket(const Server_Socket&) = delete;
        Server_Socket(Server_Socket&&) = delete;

        int Create();
        int createSocket();
        int bindSocket();
        int connectSocket();
        int listenConnection(int queueLen=5);
        int acceptConnection();
        
        int Close(int Socket_FD_num);
        int Shutdown(int Socket_FD_num, int behavior);

        int Send(int Socket_FD_num, void *data, size_t len);
        int Receive(int Socket_FD_num, void *data, size_t len);
        int Sendto(std::string ip, std::string port, const std::string &msg);
        int Receivefrom(std::string ip, std::string port, std::string &msg);

        int run_poll();
        int run();
        
        int getSocketFD(int Socket_FD_num);
        std::vector<int>& getFDList();
        void printIPaddr();
        // getpeername()
        // gethostname()
        // gethostbyname()
};

Server_Socket::Server_Socket(const char *ip, std::string server, int protocol, int connections){
    _IP = ip ? ip : "";
    _server = server;
    _protocol = protocol;
    _connections = connections;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = _protocol;
    hints.ai_flags = AI_PASSIVE;

    try{
        int status = getaddrinfo(ip, _server.c_str(), &hints, &serverinfo);
        if(status != 0) throw(gai_strerror(status));
    }
    catch(const char *err){
        std::cerr << err << std::endl;
        exit(-1);
    }
    // FD_ZERO(&connected_client_file_descriptor);
    std::cout << FRONT_GREEN << "Construct server socket info successfully!" << RESET_COLOR << std::endl;
    gethostname(hostName, HOSTNAME_MAXLEN);
    std::cout << "local name: " << BOLD << hostName << RESET_COLOR << std::endl;
    printIPaddr();
}

Server_Socket::~Server_Socket(){
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
    std::cout << FRONT_GREEN << "Destruct server socket successfully!" << RESET_COLOR << std::endl;
}

int Server_Socket::Create(){
    std::cout << "start..." <<std::endl;
    try{
        std::cout << FRONT_YELLOW << "choosing available address..." << RESET_COLOR <<std::endl;
        int yes = 1;
        struct addrinfo *p = serverinfo;
        for(; p != nullptr; p = p->ai_next){
            _server_socket_file_descriptor = socket(p->ai_family, p->ai_socktype, p->ai_protocol); 
            if(_server_socket_file_descriptor < 0)continue;
            if(bindSocket() < 0){
                close(_server_socket_file_descriptor);
                continue;
            }
            break;
        }
        freeaddrinfo(serverinfo);
        if(p == NULL) throw("invalid serverinfo!");
        if(listenConnection() != 0) throw("listen error!");
        std::cout << FRONT_GREEN << "server listen FD:" << _server_socket_file_descriptor << RESET_COLOR << std::endl;
    }
    catch(const char *err){
        std::cerr << FRONT_RED << err << RESET_COLOR << std::endl;
        return -1;
    }
    std::cout << FRONT_GREEN << "create socket successfully!" << RESET_COLOR << std::endl;
    return 0;
}

int Server_Socket::createSocket(){
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

int Server_Socket::bindSocket(){
    // bind the special port and IP to the socket
    // int reuse = 1;
    // setsockopt(_server_socket_file_descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));
    try{
        int yes = 1;
        setsockopt(_server_socket_file_descriptor, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
        int status = bind(_server_socket_file_descriptor, serverinfo->ai_addr, serverinfo->ai_addrlen);
        if(status == -1) throw("bind error!");
    }
    catch(const char *err){
        std::cerr << FRONT_RED << err << RESET_COLOR << std::endl;
        printf("-Error NO.%d: %s\n", errno, strerror(errno));
        return errno;
    }
    std::cout << FRONT_GREEN << "bind successfully!" << RESET_COLOR << std::endl;
    return 0;
}

int Server_Socket::connectSocket(){
    // establish connection
    try{
        int status = connect(_server_socket_file_descriptor, serverinfo->ai_addr, serverinfo->ai_addrlen);
        if(status == -1) throw("connect error!");
    }
    catch(const char *err){
        std::cerr << FRONT_RED << err << RESET_COLOR << std::endl;
        printf("-Error NO.%d: %s\n", errno, strerror(errno));
        return errno;
    }
    std::cout << FRONT_GREEN << "connect successfully!" << RESET_COLOR << std::endl;
    return 0;
}

int Server_Socket::listenConnection(int queueLen){
    // need to call bind() before call listen() so that the server is running on a specific port. 
    /* 
        the sequence of calls is:
        getaddrinfo();
        socket();
        bind();
        listen();
        (accept();)
    */
    try{
        int status = listen(_server_socket_file_descriptor, queueLen);
        if(status == -1) throw("listen error!");
    }
    catch(const char *err){
        std::cerr << FRONT_RED << err << RESET_COLOR << std::endl;
        printf("-Error NO.%d: %s\n", errno, strerror(errno));
        return errno;
    }
    std::cout << FRONT_GREEN << "listen successfully!" << RESET_COLOR << std::endl;
    return 0;
}

int Server_Socket::acceptConnection(){
    /* 
        call accept() to get the pending connection. 
        It’ll return a new socket file descriptor to use for this single connection.
        The original one is still listening for more new connections, 
        and the newly created one is finally ready to send() and recv().

        If you’re only getting one single connection, 
        you can close() the listening sockfd in order to prevent more incoming connections on the same port.
    */
    std::cout << FRONT_YELLOW << "accepting..." << RESET_COLOR << std::endl;
    try{
        struct sockaddr_storage client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int new_fd = accept(_server_socket_file_descriptor, (struct sockaddr *)&client_addr, &addr_len);
        if(new_fd == -1) throw("accept error!"); 
        std::lock_guard<std::mutex> lock(FD_mutex);
        connected_client_file_descriptor.push_back(new_fd);
        // FD_SET(new_fd, &connected_client_file_descriptor);
    }
    catch(const char *err){
        std::cerr << FRONT_RED << err << RESET_COLOR << std::endl;
        printf("-Error NO.%d: %s\n", errno, strerror(errno));
        return errno;
    }
    printf("%saccept a connection!%s\n-FD_num:%lu, FD:%d\n", FRONT_GREEN, RESET_COLOR, connected_client_file_descriptor.size() - 1, connected_client_file_descriptor.back());
    return connected_client_file_descriptor.size() - 1;
}

int Server_Socket::Close(int Socket_FD_num){
    int _FD = 0;
    try{
        _FD = connected_client_file_descriptor.at(Socket_FD_num);
        int status = close(_FD);
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
    std::lock_guard<std::mutex> lock(FD_mutex);
    connected_client_file_descriptor.erase(connected_client_file_descriptor.begin() + Socket_FD_num);
    std::cout << "close " << Socket_FD_num << ":" << BOLD << _FD << RESET_COLOR << "successfully!" << std::endl;
    return 0;
}

int Server_Socket::Shutdown(int Socket_FD_num, int behavior){
    int _FD = 0;
    try{
        _FD = connected_client_file_descriptor.at(Socket_FD_num);
        int status = shutdown(_FD, behavior);
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
    if(behavior == 2) {
        std::lock_guard<std::mutex> lock(FD_mutex);
        connected_client_file_descriptor.erase(connected_client_file_descriptor.begin() + Socket_FD_num);
    }
    std::cout << "shutdown " << Socket_FD_num << ":" << BOLD << _FD << RESET_COLOR << "successfully!" << std::endl;
    std::cout << "behavior:" << FRONT_YELLOW << behavior << RESET_COLOR << std::endl;
    return 0;
}

int Server_Socket::Send(int Socket_FD_num, void *data, size_t len){
    void *_ = data;
    try{
        int status = send(connected_client_file_descriptor.at(Socket_FD_num), _, len, 0);
        while(status != 0){
            if(status == -1) throw("tcp send error!");
            _ = static_cast<void*>(static_cast<char*>(data) + status);
            len -= status;
            status = send(connected_client_file_descriptor[Socket_FD_num], _, len, 0);
        }
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
    std::cout << FRONT_DARKGREEN << Socket_FD_num << " <--- " << RESET_COLOR << (char*)data << std::endl;
    return 0;
}

int Server_Socket::Receive(int Socket_FD_num, void *data, size_t len){
    int status = 0;
    try{
        status = recv(connected_client_file_descriptor.at(Socket_FD_num), data, len, 0);
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
        std::cout << FRONT_BLACK 
            << "receive 0 byte data! the remote side has closed the connection!" 
            << RESET_COLOR << std::endl;
    }
    return 0;
}

int Server_Socket::Sendto(std::string ip, std::string port, const std::string &msg){
    // TODO
    return 0;
}

int Server_Socket::Receivefrom(std::string ip, std::string port, std::string &msg){
    // TODO
    return 0;
}

int Server_Socket::run_poll(){
    // TODO
    return 0;
}

int Server_Socket::getSocketFD(int Socket_FD_num){
    try{
        int _FD = connected_client_file_descriptor.at(Socket_FD_num);
        return _FD;
    }
    catch(const std::out_of_range& err){
        std::cerr << FRONT_RED << err.what() << std::endl;
        return -1;
    }
}

std::vector<int>& Server_Socket::getFDList(){
    return connected_client_file_descriptor;
}

void Server_Socket::printIPaddr(){
    // serverinfo is the head of a linked list
    printf("IP addresses for %s%s:%s\n", BOLD, _IP.size() ? _IP.c_str() : "INET_ADDR_ANY", RESET_COLOR);
    for(auto p = serverinfo; p != nullptr; p = p->ai_next) {
        void *addr;
        std::string ipver;
        char ipstr[INET6_ADDRSTRLEN];

        if(p->ai_family == AF_INET){
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = std::string(FRONT_PURPLE) + "IPv4" + std::string(RESET_COLOR);
        } 
        else{
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = std::string(FRONT_DARKGREEN) + "IPv6" + std::string(RESET_COLOR);
        }

        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        printf("  %s: %s\n", ipver.c_str(), ipstr);
    }
}

int main(int argc, char **argv){
    int protocol = SOCK_STREAM;
    char *p = nullptr;
    Server_Socket ttt(p, "10001", protocol, 64);
    ttt.Create();
    return 0;
}