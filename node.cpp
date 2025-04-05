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
#include <cstring>
#include <algorithm>
#include <mutex>
#include <unistd.h>


using namespace std;

long long start_range, end_range, checkpoint;

atomic<bool> password_found(false);
atomic<long long> total_guesses(0);
vector<thread> worker_threads;
mutex checkpoint_mtx;
mutex mtx;

int worker_socket;
string hashed_password, salt;

vector<string> messages_text {"SETUP", "REQUEST", "ASSIGN", "CHECKPOINT", "FOUND", "STOP", "CONTINUE"};

void divide_work(int num_threads);

/**
 * Converts the ASCII index into its associated string representation.
 * @param index ASCII index
 * @return string representation of password
 */
string index_to_password(long long index) {
    if (index == 0) {
        return string{1, '\0'};
    }
    string password;
    while (index) {
        password.push_back(static_cast<char>(index % 256));
        index /= 256;
    }
    reverse(password.begin(), password.end());
    return password;
}

/**
 * Receives the message from the given socket.
 * @param client_socket
 * @param msg
 * @return bool Whether any message was received.
 */
bool recv_message(int client_socket, Message &msg) {
    uint32_t size;

    if (recv(client_socket, &size, sizeof(size), MSG_WAITALL) <= 0) {
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
    string serialized = msg.serialize();
    uint32_t size = serialized.size();

    send(client_socket, &size, sizeof(size), 0);
    send(client_socket, serialized.c_str(), serialized.size(), 0);
}

/**
 * Starts the connection with the server
 * @param server_ip
 * @param server_port
 */
void start_conn(const string &server_ip, int server_port) {
    int sock;
    bool ipv6;
    if (server_ip.find(':') != string::npos) {
        sock = socket(AF_INET6, SOCK_STREAM, 0);
        ipv6 = true;
    } else {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        ipv6 = false;
    }

    if (sock == -1) {
        perror("Socket Failed!");
        exit(1);
    }

    if (ipv6) {
        struct sockaddr_in6 server_addr{};
        server_addr.sin6_family = AF_INET6;
        server_addr.sin6_port = htons(server_port);

        if (inet_pton(AF_INET6, server_ip.c_str(), &server_addr.sin6_addr) <= 0) {
            cerr << "Invalid IPv6 address format. \n";
            close(sock);
            return;
        }

        if (connect(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) <= 0) {
            cerr << "IPv6 connection failed with " << server_ip << " on port: " << server_port << endl;
            close(sock);
            return;
        }
    } else {
        struct sockaddr_in server_addr4{};
        server_addr4.sin_family = AF_INET;
        server_addr4.sin_port = htons(server_port);

        if (inet_pton(AF_INET, server_ip.c_str(), &server_addr4.sin_addr) <= 0) {
            cerr << "Invalid IPv4 address format. \n";
            close(sock);
            return;
        }

        if (connect(sock, (struct sockaddr *) &server_addr4, sizeof(server_addr4)) < 0) {
            cerr << "IPv4 connection failed with " << server_ip << " on port: " << server_port << endl;
            close(sock);
            return;
        }
    }

    cout << "Connected to server: " << server_ip << " on port: " << server_port << endl;
    worker_socket = sock;
}

bool receive_setup() {
    Message req{Message::REQUEST};
    send_message(worker_socket, req);

    Message resp;
    if (!recv_message(worker_socket, resp)) {
        cerr << "Failed to receive SETUP message from server.\n";
        return false;
    }

    if (resp.type != Message::SETUP || !resp.Setup_Data) {
        cerr << "Invalid SETUP message received.\n";
    }

    hashed_password = resp.Setup_Data->hashed_password;
    salt = resp.Setup_Data->salt;
    checkpoint = resp.Setup_Data->checkpoint;

    cout << "Received SETUP message:\n";
    cout << "Hashed Password: " << hashed_password << endl;
    cout << "Salt: " << salt << endl;
    cout << "Checkpoint: " << checkpoint << endl;

    return true;
}


/**
 * Requests work from the server.
 * @param num_threads
 */
void request_work(int num_threads) {
    cout << "Requesting Work" << endl;

    bool success = false;
    int retries = 0;
    const int MAX_RETRIES = 5;

    while (!success && retries < MAX_RETRIES) {
        Message request_msg(Message::REQUEST);
        send_message(worker_socket, request_msg);

        Message resp;
        bool received = recv_message(worker_socket, resp);
        cout << messages_text[resp.type] << endl;

        if (received && resp.type == Message::ASSIGN
            && resp.Assign_Data) {
            start_range = resp.Assign_Data->range.first;
            end_range = resp.Assign_Data->range.second;
            divide_work(num_threads);
            success = true;
        } else {
            cerr << "Failed to receive valid ASSIGN message. Retrying ("
                 << (retries + 1) << "/" << MAX_RETRIES << ")...\n";
            retries++;
        }
    }

    if (!success) {
        cerr << "Max retries reached. Couldn't receive valid setup or assign data. Attempting to reconnect...\n";
        close(worker_socket);
    }
}

/**
 * Uses brute force cracking and multithreading to find the password.
 * @param node_id Used when communicating with the server.
 * @param start of the password ranges
 * @param end of the password ranges
 */
void crack_password(int node_id, long long start, long long end, vector<pair<long long, long long>> *ranges) {
    struct crypt_data crypt_buffer{};
    crypt_buffer.initialized = 0;

    long long guesses_made = 0;
    long long current_start = start;

    for (long long i = start; i <= end && !password_found; ++i) {
        string password_guess = index_to_password(i);
        const char *gen_hash = crypt_r(password_guess.c_str(), salt.c_str(), &crypt_buffer);

        if (!gen_hash) {
            cerr << "Error: crypt_r() failed for password: " << password_guess << endl;
            continue;
        }

        guesses_made++;
        total_guesses++;

        if (strcmp(gen_hash, hashed_password.c_str()) == 0) {
            lock_guard<mutex> lock(mtx);
            password_found = true;

            Message found_msg{Message::FOUND, Message::Found{node_id, i}};
            if (worker_socket > 0) {
                send_message(worker_socket, found_msg);
            } else {
                cerr << "Error: worker_socket not initialized.\n";
            }
            return;
        }

        if (guesses_made % checkpoint == 0) {
            lock_guard<mutex> lock(checkpoint_mtx);
            ranges->clear();
            ranges->emplace_back(current_start, i);
            Message checkpoint_msg{Message::CHECKPOINT, Message::Checkpoint{worker_socket, *ranges}};
            cout << "Sending Checkpoint to the server" << endl;
            for (const auto &range: *ranges) {
                cout << "Checkpoint Range: " << range.first << "-" << range.second << endl;
            }
            send_message(worker_socket, checkpoint_msg);

            Message resp;
            if (!recv_message(worker_socket, resp)) {
                cerr << "Failed to receive response to checkpoint.\n";
                return;
            }

            if (resp.type == Message::STOP) {
                cout << "STOP message received. Shutting down...\n";
                password_found = true;
                return;
            } else if (resp.type == Message::CONTINUE) {
                cout << "CONTINUE message received. Continuing Work...\n";
            } else {
                cerr << "UNEXPECTED message received. Proceeding...\n";
                cerr << "Message Type: " << messages_text[resp.type] << endl;
            }

            current_start = i + 1;
        }
    }

    if (!password_found && current_start <= end) {
        lock_guard<mutex> lock(checkpoint_mtx);
        ranges->clear();
        ranges->emplace_back(current_start, end);
        Message checkpoint_msg{Message::CHECKPOINT, Message::Checkpoint{worker_socket, *ranges}};
        cout << "Sending Final Checkpoint to the server" << endl;
        for (const auto &range: *ranges) {
            cout << "Checkpoint Range: " << range.first << "-" << range.second << endl;
        }
        send_message(worker_socket, checkpoint_msg);

        Message resp;
        if (!recv_message(worker_socket, resp)) {
            cerr << "Failed to receive response to checkpoint.\n";
            return;
        } else if (resp.type == Message::STOP) {
            cout << "STOP message received. Shutting down...\n";
            password_found = true;
            return;
        }
    }
}


/**
 * Divides the workload between the threads based on the number of threads.
 */
void divide_work(int num_threads) {
    worker_threads.clear();
    vector<pair<long long, long long>> attempted_ranges;
    cout << "Dividing work across " << num_threads << " threads." << endl;
    long long range_per_thread = (end_range - start_range + 1) / num_threads;

    for (int i = 0; i < num_threads; ++i) {
        long long thread_start = start_range + i * range_per_thread;
        long long thread_end = (i == num_threads - 1)
                               ? end_range : min(thread_start + range_per_thread - 1, end_range);

        cout << "Thread " << i << " -> Start: " << thread_start << ", End: " << thread_end << endl;

        try {
            worker_threads.emplace_back(crack_password, i, thread_start, thread_end, &attempted_ranges);
        } catch (const std::system_error &e) {
            cerr << "Thread creation failed: " << e.what() << endl;
            exit(1);
        }
    }

    for (auto &thread: worker_threads) {
        thread.join();
    }
}


int main(int argc, char *argv[]) {
    if (argc != 4) {
        cerr << "Usage: " << argv[0] << " --server --port --thread\n";
        return 1;
    }

    string server_ip = argv[1];
    int server_port = stoi(argv[2]);
    int num_threads = stoi(argv[3]);
    if (num_threads < 1) {
        cerr << "Error: At least 1 thread needed to run. \n";
        return 1;
    }


    cout << "Server IP: " << server_ip << endl;
    cout << "Server Port: " << server_port << endl;
    cout << "Number of Threads: " << num_threads << endl;

    start_conn(server_ip, server_port);

    if (!receive_setup()) {
        cerr << "Failed during setup. Exiting.\n";
        close(worker_socket);
        return 1;
    }

    while (true) {
        request_work(num_threads);

        Message stop_msg;
        if (recv_message(worker_socket, stop_msg) && stop_msg.type == Message::STOP) {
            cout << "Received STOP signal from server. Exiting...\n";
            break;
        }

        if (password_found) {
            cout << "Password Found. Stopping worker node.\n";
            break;
        }
    }


    close(worker_socket);
    return 0;
}


