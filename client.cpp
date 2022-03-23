#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <atomic>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include "include/color.hpp"

const int MAX_SERVER_NAME_LEN = 64;
const int MAX_BUF_LEN = 256;

class Client_Socket{
    private:
        int _protocol;
        std::string _server;
        std::string _IP;
        int server_FD;
        char serverAddr[MAX_SERVER_NAME_LEN] = {0};
        struct addrinfo hints;
        struct addrinfo *serverinfo;
        std::thread receive;
        int Receive();
        std::atomic<int> recv_status;
        void* get_in_addr(struct sockaddr *sa);

    public:
        Client_Socket() = delete;
        Client_Socket(const char *ip, std::string server, int protocol);
        virtual ~Client_Socket();
        Client_Socket(const Client_Socket&) = delete;
        Client_Socket(Client_Socket&&) = delete;

        int create();
        void run();

};

Client_Socket::Client_Socket(const char *ip, std::string server, int protocol){
    _IP = ip ? ip : "";
    _server = server;
    _protocol = protocol;

    memset(&hints, 0, sizeof(hints)); // make sure the struct is empty
    hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
    hints.ai_socktype = _protocol; // TCP stream sockets

    try{
        int status = getaddrinfo(_server.c_str(), ip, &hints, &serverinfo);
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
    std::cout << "Destruct client socket successfully!" << std::endl;
}

int Client_Socket::create(){
    std::cout << "start..." <<std::endl;
    try{
        std::cout << FRONT_YELLOW << "choosing available address..." << RESET_COLOR <<std::endl;
        int yes = 1;
        struct addrinfo *p = serverinfo;
        for(; p != nullptr; p = p->ai_next){
            server_FD = socket(p->ai_family, p->ai_socktype, p->ai_protocol); 
            if(server_FD < 0)continue;

            if (connect(server_FD, p->ai_addr, p->ai_addrlen) == -1) {
                close(server_FD);
                continue;
            }
            break;
        }
        if(p == NULL) throw("invalid serverinfo!");
        freeaddrinfo(serverinfo);
        inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), serverAddr, sizeof(serverAddr));
        std::cout << "client connecting to " << BOLD << serverAddr << RESET_COLOR << std::endl;
    }
    catch(const char *err){
        std::cerr << FRONT_RED << err << RESET_COLOR << std::endl;
        return -1;
    }
    std::cout << FRONT_GREEN << "connect to server successfully!" << RESET_COLOR << std::endl;
    return 0;
}

int Client_Socket::Receive(){
    int status = 0;
    while(true){
        char buf[MAX_BUF_LEN] = {0};
        try{
            status = recv(server_FD, buf, sizeof(buf), 0);
            if(status == -1) throw("receive error!");
        }
        catch(const char *err){
            std::cerr << FRONT_RED << err << RESET_COLOR << std::endl;
            recv_status = 0;
            return -1;
        }
        // std::cout << FRONT_DARKGREEN << "server" << RESET_COLOR;
        std::cout << FRONT_BLUE << "---> " << RESET_COLOR << buf << std::endl;
        if(status == 0){
            std::cout << FRONT_BLACK 
                << "receive 0 byte data! the remote side has closed the connection!" 
                << RESET_COLOR << std::endl;
        }
    }
    recv_status = 0;
    return 0;
}

void Client_Socket::run(){
    std::cout << "--------------------" << std::endl;
    recv_status = 1;
    receive = std::thread(&Client_Socket::Receive);
    receive.detach();
    
    while(true){
        std::string msg;
        std::getline(std::cin, msg);
        char *data = static_cast<char*>(malloc(msg.length() + 1));
        strcpy(data, msg.c_str());
        void *_ = data;
        int len = msg.length() + 1;
        try{
            int status = send(server_FD, _, len, 0);
            while(status != 0){
                if(status == -1) throw("send error!");
                _ = static_cast<void*>(static_cast<char*>(data) + status);
                len -= status;
                status = send(server_FD, _, len, 0);
            }
            if(recv_status == 0){
                break;
            }
        }
        catch(const char *err){
            std::cerr << FRONT_RED << err << RESET_COLOR << std::endl;
            printf("-Error NO.%d: %s\n", errno, strerror(errno));
            break;
        }
        std::cout << FRONT_DARKGREEN << "server <--- " << RESET_COLOR << (char*)data << std::endl;
        break;
    }
    close(server_FD);
}

void* Client_Socket::get_in_addr(struct sockaddr *sa){
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    else return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(){
    Client_Socket client1("localhost", "10001", SOCK_STREAM);
    client1.create();
    client1.run();
    return 0;
}