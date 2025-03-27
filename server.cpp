//
// Created by waleed on 26/03/25.
//

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

bool password_found = false;

using namespace std;

struct WorkerInfo {
    int socket;
    long long start_ascii;
    long long end_ascii;
    string last_checkpoint;
};


//pair<long long, long long> generate_next_range(
//        long long range_size, long long range_start, long long range_end) {
//    static long long range_start = 0;
//}

void start_server(int port) {
    int server_socket = socket(AF_INET6, SOCK_STREAM, 0);

    if (server_socket < 0) {
        cerr << "Unable to create socket.\n";
        exit(1);
    }

    int opt = 0;
    setsockopt(server_socket, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));

    sockaddr_in6 server_addr{};
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(port);
    server_addr.sin6_addr = in6addr_any;

    if (bind(server_socket, (sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Unable to bind socket.\n";
        close(server_socket);
        exit(1);
    }

    listen(server_socket, 10);
    cout << "Server listening on port " << port << " (IPv4 & IPv6)\n";

    while(!password_found) {
        sockaddr_in6 client_addr{};
        socklen_t client_size = sizeof(client_addr);
        int client_socket = accept(server_socket, (sockaddr *)&client_addr, &client_size);

        if (client_socket >= 0) {
//            char* buffer = "hello";
            send(client_socket,"Hello", 5, 0);
        }
    }

    close(server_socket);
}

int main(int argc, char *argv[]){
    if (argc != 6) {
        cerr << "Usage: " << argv[0] << " --port --hash --work-size --checkpoint --timeout\n";
        return 1;
    }

    int port = stoi(argv[1]);
    char* hash = argv[2];
    int work_size = stoi(argv[3]);
    int checkpoint = stoi(argv[4]);
    int timeout = stoi(argv[5]);


    start_server(port);

    return 0;
}
