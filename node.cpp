//
// Created by waleed on 26/03/25.
//

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <atomic>
#include "Message.h"
#include <thread>
#include <crypt.h>
#include <string.h>
#include <mutex>

using namespace std;

long long start_range, end_range;

atomic<bool> password_found(false);
atomic<long long> total_guesses(0);
long long found_password;
vector<thread> worker_threads;

int worker_socket;
char hashed_password[256], salt[64];
int num_threads;
mutex mtx;

string  index_to_password(long long index) {
    string password;
    while (index > 0) {
        password.insert(password.begin(), static_cast<char> (index % 256));
        index /= 256;
    }
    return password.empty() ? string (1, '\0') : password;
}

/**
 * Receives the message from the given socket.
 * @param client_socket
 * @param msg
 * @return bool Whether any message was received.
 */
bool recv_message(int client_socket, Message &msg) {
    uint32_t  size;

    if (recv(client_socket, &size, sizeof (size), 0) <= 0) {
        cerr << "Failed to receive message size or client disconnected." << endl;
        return false;
    }

    string buffer(size, '\0');
    if (recv(client_socket, buffer.data(), size, 0) <= 0) {
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

void start_conn(const string &server_ip, int server_port) {
    int sock = socket(AF_INET6, SOCK_STREAM, 0);

    if (sock == -1) {
        perror("Socket Failed!");
        exit(1);
    }

    struct sockaddr_in6 server_addr{};
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(server_port);
    if (inet_pton(AF_INET6, server_ip.c_str(), &server_addr.sin6_addr) <= 0) {
        sockaddr_in server_addr_ipv4{};
        server_addr_ipv4.sin_family = AF_INET;
        server_addr_ipv4.sin_port = htons(server_port);
        if (inet_pton(AF_INET, server_ip.c_str(), &server_addr_ipv4.sin_addr) <= 0) {
            cerr << "Invalid IP address format. \n";
            return;
        }
        if (connect(sock, (struct sockaddr *)&server_addr_ipv4, sizeof (server_addr_ipv4)) < 0) {
            cerr << "Connection failed with " + server_ip + " on port: " + to_string(server_port);
        }
    } else {
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) <= 0) {
            cerr << "Connection failed with " + server_ip + " on port: " + to_string(server_port);
        }
    }

    cout << "Connected to server: " << server_ip << " on port: " << server_port << endl;
    worker_socket = sock;
}



void request_work() {
    Message request_msg(Message::REQUEST);
    send_message(worker_socket, request_msg);

    Message resp;
    recv_message(worker_socket, resp);

    if (resp.type == Message::ASSIGN) {
        start_range = resp.Assign_Data->range.first;
        end_range = resp.Assign_Data->range.second;
    }
}

void crack_password(int node_id, long long start, long long end) {
    struct crypt_data crypt_buffer{};
    crypt_buffer.initialized = 0;

    for (long long i = start; i <= end && !password_found; ++i) {
        string password_guess = index_to_password(i);
        const char *gen_hash = crypt_r(password_guess.c_str(), salt, &crypt_buffer);

        total_guesses++;

        if (strcmp(gen_hash, hashed_password) == 0) {
            lock_guard<mutex> lock(mtx);
            password_found = 1;

            Message found_msg{Message::FOUND, Message::Found{node_id, i}};
            if (worker_socket > 0) {
                send_message(worker_socket, found_msg);
            } else {
                cerr << "Error: worker_socket not initialized.\n";
            }
            return;
        }
        // TODO Deal with checkpointing. Not for now. IGNORE
    }
}



void divide_work() {
    long long range_per_thread = (end_range - start_range + 1) / num_threads;
    for (int i = 0; i < num_threads; ++i) {
        long long thread_start = start_range + i * range_per_thread;
        long long thread_end = (i == num_threads - 1) ? end_range : thread_start + range_per_thread - 1;
        worker_threads.emplace_back(crack_password, i, thread_start, thread_end);
    }
    
    for (auto &thread : worker_threads) {
        thread.join();
    }
}


int main(int argc, char *argv[]){
    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " --server --port --thread\n";
        return 1;
    }

    string server_ip = argv[1];
    int server_port = stoi(argv[2]);
    num_threads = stoi(argv[3]);
    if (num_threads < 1) {
        cerr << "Error: At least 1 thread needed to run. \n";
        return 1;
    }

    cout << "Server IP: " << server_ip << endl;
    cout << "Server Port: " << server_port << endl;
    cout << "Number of Threads: " << num_threads << endl;

    start_conn(server_ip, server_port);
    request_work();
    divide_work();


    return 0;
}


