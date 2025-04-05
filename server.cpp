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
vector<int> node_sockets;
atomic<bool> password_found(false);
mutex active_nodes_mutex;

// Stores checkpoints received so r
mutex checkpoint_mutex;

static atomic<long long> next_range_start(0); // Stores the current range.

unordered_map<int, pair<long long, long long>> active_nodes;
unordered_map<int, chrono::steady_clock::time_point> node_last_seen;
unordered_map<int, vector<pair<long long, long long>>> checkpoints;
char hashed_password[256], salt[64];
long long checkpoint;

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
 * Handle Workers
 * @param client_socket FD of the client
 * @param work_size The password guesses assigned per worker
 */
void handle_worker(int client_socket, long long work_size, int timeout_seconds) {
    bool setup_handled = false;
    while (!password_found) {
        Message msg;

        if (!recv_message(client_socket, msg)) {
            {
                lock_guard<mutex> lock(active_nodes_mutex);
                if (active_nodes.count(client_socket)) {
                    pair<long long, long long> lost_ranges = active_nodes[client_socket];

                    lock_guard<mutex> lock1(checkpoint_mutex);
                    if (checkpoints.count(client_socket)) {
                        vector<pair<long long, long long>> &ranges = checkpoints[client_socket];

                        vector<pair<long long, long long>> remaining_work;
                        long long assigned_start = lost_ranges.first;
                        long long assigned_end = lost_ranges.second;

                        for (auto &[chk_start, chk_end]: ranges) {
                            if (chk_start > assigned_start) {
                                remaining_work.emplace_back(assigned_start, chk_start - 1);
                            }
                            assigned_start = chk_end + 1;
                        }
                        if (assigned_start <= assigned_end) {
                            remaining_work.emplace_back(assigned_start, assigned_end);
                        }

                        for (auto &range: remaining_work) {
                            checkpoints[-1].push_back(range);
                        }
                        checkpoints.erase(client_socket);
                    } else {
                        checkpoints[-1].push_back(lost_ranges);
                    }

                    next_range_start.store(lost_ranges.first);
                    active_nodes.erase(client_socket);
                }
            }
            close(client_socket);
            return;
        }
        {
            lock_guard<mutex> lock(checkpoint_mutex);
            node_last_seen[client_socket] = chrono::steady_clock::now();
        }

        if (msg.type == Message::REQUEST) {
            if (!setup_handled) {
                Message setup_msg(Message::SETUP, Message::Setup{
                        client_socket, checkpoint, hashed_password, salt
                });
                send_message(client_socket, setup_msg);
                setup_handled = true;
                cout << "Setup Handled for node: " << client_socket << endl;
            }

            pair<long long, long long> range;
            {
                lock_guard<mutex> lock(checkpoint_mutex);
                if (!checkpoints[-1].empty()) {
                    range = checkpoints[-1].back();
                    checkpoints[-1].pop_back();
                } else {
                    range = get_range(next_range_start, work_size);
                    next_range_start.fetch_add(work_size);
                }
            }

            {
                lock_guard<mutex> lock(active_nodes_mutex);
                active_nodes[client_socket] = range;
            }

            Message assign_msg(Message::ASSIGN, Message::Assign{
                    client_socket, range
            });
            send_message(client_socket, assign_msg);
            cout << "Range Given to Node: " << client_socket << " "
                 << range.first << "-" << range.second << endl;

        } else if (msg.type == Message::FOUND) {
            password_found = true;
            cout << "Password found by node: " << msg.Found_Data->node_id
                 << " at index " << msg.Found_Data->pwd_idx << "!\n";
            correct_password = index_to_password(msg.Found_Data->pwd_idx);
            cout << "Correct Password: " << correct_password << endl;
        } else if (msg.type == Message::CHECKPOINT) {
            cout << "Checkpoint for Node: " << msg.Checkpoint_Data->node_id << endl;
            for (auto &range : msg.Checkpoint_Data->ranges) {
                cout << "Range: " << range.first << "-" << range.second << endl;
            }
            {
                lock_guard<mutex> lock(checkpoint_mutex);
                checkpoints[msg.Checkpoint_Data->node_id] = msg.Checkpoint_Data->ranges;
            }

            Message continue_msg{Message::CONTINUE};
            send_message(client_socket, continue_msg);
        }
    }
}

void monitor_timeouts(int timeout_seconds) {
    while (!password_found) {
        this_thread::sleep_for(chrono::seconds(10));

        lock_guard<mutex> lock(checkpoint_mutex);
        auto now = chrono::steady_clock::now();

        for (auto it = node_last_seen.begin(); it != node_last_seen.end();) {
            int node_id = it->first;
            auto last_seen = it->second;

            if (chrono::duration_cast<chrono::seconds>(now - last_seen).count() > timeout_seconds) {
                cout << "Node " << node_id << " timed out! Reassigning work.\n";

                lock_guard<mutex> lock_nodes(active_nodes_mutex);
                if (active_nodes.count(node_id)) {
                    checkpoints[-1].push_back(active_nodes[node_id]);
                    active_nodes.erase(node_id);
                }
                checkpoints.erase(node_id);
                it = node_last_seen.erase(it);
            } else {
                ++it;
            }
        }
    }
}

/**
 * Starts the server
 * @param port
 * @param work_size
 */
void start_server(int port, long long work_size, int timeout_seconds) {
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

    if (bind(server_socket, (sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        cerr << "Unable to bind socket.\n";
        close(server_socket);
        exit(1);
    }

    listen(server_socket, MAX_CLIENTS);
    cout << "Server listening on port " << port << endl;


    vector<thread> worker_threads;
    thread timeout_thread(monitor_timeouts, timeout_seconds);

    while (!password_found) {
        sockaddr_in6 client_addr{};
        socklen_t client_size = sizeof(client_addr);
        int client_socket = accept(server_socket, (sockaddr *) &client_addr, &client_size);

        if (client_socket < 0) {
            cerr << "Socket closed or unavailable.\n";
        } else {
            cout << "Connected to Node: " << client_socket << endl;
            {
                lock_guard<mutex> lock(active_nodes_mutex);
                node_sockets.push_back(client_socket);
            }
            worker_threads.emplace_back(handle_worker, client_socket, work_size, timeout_seconds);

        }
    }

    cout << "Password found! Shutting down server...\n";
    timeout_thread.detach();

    {
        lock_guard<mutex> lock(active_nodes_mutex);
        for (int sock: node_sockets) {
            Message stop_msg(Message::STOP);
            send_message(sock, stop_msg);
            close(sock);
        }
        node_sockets.clear();
    }

    for (auto &tt: worker_threads) {
        if (tt.joinable()) tt.join();
    }

    close(server_socket);
}

/**
 * Get the hashing algorithm based on the prescript.
 * @param pwd_hash The hasehd password
 * @return The Hashing Algorithm
 */
const char *get_hash_type(const char *pwd_hash) {
    if (strncmp(pwd_hash, "$1$", 3) == 0) return "MD5";
    if (strncmp(pwd_hash, "$5$", 3) == 0) return "SHA-256";
    if (strncmp(pwd_hash, "$6$", 3) == 0) return "SHA-512";
    if (strncmp(pwd_hash, "$y$", 3) == 0) return "YESCRYPT";
    if (strncmp(pwd_hash, "$2a$", 3) == 0 ||
        strncmp(pwd_hash, "$2b$", 3) == 0 ||
        strncmp(pwd_hash, "$2y$", 3) == 0)
        return "BCRYPT";
    return "Unknown";
}


/**
 * Extracts the salt of the hashed password to the salt_buffer.
 * @param hashed_pwd
 * @param salt_buffer
 * @param buffer_size
 */
void extract_salt(char *hashed_pwd, char *salt_buffer, size_t buffer_size) {
    size_t dollar_count = 0;
    const char *ptr = hashed_pwd;

    while (*ptr && dollar_count < 3) {
        if (*ptr == '$') dollar_count++;
        ptr++;
    }

    if (dollar_count < 3) {
        salt_buffer[0] = '\0';
        return;
    }

    // BCRYPT salt must include 22 chars after the 3rd dollar sign.
    if (strcmp(get_hash_type(hashed_pwd), "BCRYPT") == 0) {
        ptr += 22;
    }

    size_t salt_len = ptr - hashed_pwd;
    if (salt_len >= buffer_size) {
        salt_len = buffer_size - 1;
    }
    strncpy(salt_buffer, hashed_pwd, salt_len);
    salt_buffer[salt_len] = '\0';

}


int main(int argc, char *argv[]) {
    if (argc != 6) {
        cerr << "Usage: " << argv[0] << " --port --hash --work-size --checkpoint --timeout\n";
        return 1;
    }

    int port = stoi(argv[1]);
    char *hash = argv[2];
    long long work_size = stoll(argv[3]);
    checkpoint = stoi(argv[4]);
    int timeout = stoi(argv[5]);
    extract_salt(hash, salt, sizeof(salt));
    strcpy(hashed_password, hash);
    start_server(port, work_size, timeout);

    return 0;
}
