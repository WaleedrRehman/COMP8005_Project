//
// Created by waleed on 26/03/25.
//

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <bits/stdc++.h>
#include "Message.h"

using namespace std;

#define MAX_CLIENTS 10

string correct_password;
vector <int> node_sockets;
atomic<bool> password_found(false);
static priority_queue<pair<long long, long long>> checkpoints; // Stores checkpoints received.
static pair <long long, long long> cur_pwd;

/**
 * Finds the range given the start and the size of the range
 * @param start_idx Starting point of the range
 * @param size of the range
 * @return Range [start_idx, start_idx + size]
 */
pair<long long, long long> get_range(long long start_idx, long long size) {
    long long end_idx = start_idx + size - 1;
    return {start_idx, end_idx};
}

/**
 * Receives the message from the given socket.
 * @param client_socket
 * @param msg
 * @return bool Whether any message was received.
 */
bool recv_message(int client_socket, Message &msg) {
    uint32_t  size;

    if (recv(client_socket, &size, sizeof (size), MSG_WAITALL) <= 0) {
        cerr << "Failed to receive message size or client disconnected." << endl;
        return false;
    }

    string buffer(size, '\0');
    if (recv(client_socket, buffer.data(), size, MSG_WAITALL) <= 0) {
        cerr << "Failed to receive full message" << endl;
        return false;
    }
    msg = Message::deserialize(buffer);
    return true;
}

/**
 * Sends message to the client socket given.
 * @param client_socket The node's socket id.
 * @param msg Encapsulates information to send to the node.
 */
void send_message(int client_socket, const Message &msg) {
    string  serialized = msg.serialize();
    uint32_t  size = serialized.size();

    send(client_socket, &size, sizeof(size), 0);
    send(client_socket, serialized.c_str(), serialized.size(), 0);
}


void handle_worker(int client_socket) {
    Message msg;

    if (!recv_message(client_socket, msg)) {
        close(client_socket);
        return;
    }

    if (msg.type == Message::REQUEST) {
        static long long next_rng_start = 0;

    }


}

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

    listen(server_socket, MAX_CLIENTS);
    cout << "Server listening on port " << port << " (IPv4 & IPv6)\n";

    while(!password_found) {
        sockaddr_in6 client_addr{};
        socklen_t client_size = sizeof(client_addr);
        int client_socket = accept(server_socket, (sockaddr *)&client_addr, &client_size);

        if (client_socket < 0) {
            cerr << "Socket closed or unavailable.\n";
        } else {
            node_sockets.push_back(client_socket);
            handle_worker(client_socket);

        }
    }

    close(server_socket);
}





int main(int argc, char *argv[]){
    if (argc != 3) {
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
