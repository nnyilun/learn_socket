#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <cstdio>
#include <vector>
// #include <exception>
#include <sys/socket.h>
#include <sys/types.h>
// #include <sys/wait.h>
#include <arpa/inet.h>
// #include <netinet/in.h>
// #include <csignal>
#include <cerrno>
// #include <unistd.h>
#include <netdb.h>

class Server_Socket{
    private:
        int _protocol;
        int _connections;
        std::string _server;
        std::string _IP;
        struct addrinfo hints;
        struct addrinfo *serverinfo;
        int _server_socket_file_descriptor; 
        std::vector<int> connected_client_file_descriptor;

    public:
        Server_Socket() = delete;
        Server_Socket(const char *ip, std::string server, int protocol, int connections);
        virtual ~Server_Socket();
        Server_Socket(const Server_Socket&) = delete;
        Server_Socket(Server_Socket&&) = delete;

        void createSocket();
        void bindSocket();
        void connectSocket();
        void listenConnection(int queueLen=5);
        void acceptConnection();
        void tcp_send();
        void tcp_receive();

        void printIPaddr();
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
    std::cout << "Construct server socket info successfully!" << std::endl;
    printIPaddr();
}

Server_Socket::~Server_Socket(){
    freeaddrinfo(serverinfo);
    std::cout << "Destruct server socket successfully!" << std::endl;
}

void Server_Socket::createSocket(){
    try{
        _server_socket_file_descriptor = socket(serverinfo->ai_family, serverinfo->ai_socktype, serverinfo->ai_protocol);
        if(_server_socket_file_descriptor == -1) throw("create socket error!");
    }
    catch(const char *err){
        std::cerr << err << std::endl;
        printf("Error NO.%d: %s\n", errno, strerror(errno));
        exit(-1);
    }
    std::cout << "create socket successfully!" << std::endl;
}

void Server_Socket::bindSocket(){
    // bind the special port and IP to the socket
    try{
        int status = bind(_server_socket_file_descriptor, serverinfo->ai_addr, serverinfo->ai_addrlen);
        if(status == -1) throw("bind error!");
    }
    catch(const char *err){
        std::cerr << err << std::endl;
        printf("Error NO.%d: %s\n", errno, strerror(errno));
        exit(-1);
    }
    std::cout << "bind successfully!" << std::endl;
}

void Server_Socket::connectSocket(){
    // establish connection
    try{
        int status = connect(_server_socket_file_descriptor, serverinfo->ai_addr, serverinfo->ai_addrlen);
        if(status == -1) throw("connect error!");
    }
    catch(const char *err){
        std::cerr << err << std::endl;
        printf("Error NO.%d: %s\n", errno, strerror(errno));
        exit(-1);
    }
    std::cout << "connect successfully!" << std::endl;
}

void Server_Socket::listenConnection(int queueLen){
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
        std::cerr << err << std::endl;
        printf("Error NO.%d: %s\n", errno, strerror(errno));
        exit(-1);
    }
    std::cout << "listen successfully!" << std::endl;
}

void Server_Socket::acceptConnection(){
    /* 
        call accept() to get the pending connection. 
        It’ll return a new socket file descriptor to use for this single connection.
        The original one is still listening for more new connections, 
        and the newly created one is finally ready to send() and recv().

        If you’re only getting one single connection, 
        you can close() the listening sockfd in order to prevent more incoming connections on the same port.
    */
    try{
        struct sockaddr_storage client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int new_fd = accept(_server_socket_file_descriptor, (struct sockaddr *)&client_addr, &addr_len);
        if(new_fd == -1) throw("accept error!");
        connected_client_file_descriptor.push_back(new_fd);
    }
    catch(const char *err){
        std::cerr << err << std::endl;
        printf("Error NO.%d: %s\n", errno, strerror(errno));
        exit(-1);
    }
}

void Server_Socket::printIPaddr(){
    // serverinfo is the head of a linked list
    printf("IP addresses for %s:\n", _IP.c_str());
    for(auto p = serverinfo; p != nullptr; p = p->ai_next) {
        void *addr;
        std::string ipver;
        char ipstr[INET6_ADDRSTRLEN];

        if(p->ai_family == AF_INET){
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } 
        else{
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        printf("  %s: %s\n", ipver.c_str(), ipstr);
    }
}

int main(int argc, char **argv){
    int protocol = SOCK_STREAM;
    char *p = nullptr;
    Server_Socket ttt(p, "6666", protocol, 64);

    return 0;
}