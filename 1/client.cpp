#include <iostream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <netdb.h>

class Client_Socket{
    private:
        int _protocol;
        std::string _server;
        std::string _IP;
        struct addrinfo hints;
        struct addrinfo *serverinfo;

    public:
        Client_Socket() = delete;
        Client_Socket(const char *ip, std::string server, int protocol);
        virtual ~Client_Socket();
        Client_Socket(const Client_Socket&) = delete;
        Client_Socket(Client_Socket&&) = delete;


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

int main(){

    return 0;
}