#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <atomic>
#include <vector>
#include <mutex>
#include <unordered_map>
#include "Message.h"
#include <algorithm>
#include <cstring>
#include <csignal>

using namespace std;
#define MAX_CLIENTS 10
string  correct_password;
atomic<bool> password_found(false);
mutex  global_mutex;
static atomic<long long> next_range_start(0);
unordered_map<int, pair<long long, long long>> active_nodes;
unordered_map<int, chrono::steady_clock::time_point> node_last_seen;
unordered_map<int, vector<pair<long long, long long>>> checkpoints;
char hashed_password[256], salt[64];
long long checkpoint;
fd_set read_fds;

void reassign_remaining_work(int client_sock);

/**
 * Generates the range given the start and the increment.
 * @param start_idx
 * @param size
 * @return
 */
pair<long long, long long> get_range(long long start_idx, long long size) {
    return {start_idx, start_idx + size - 1};
}

/**
 * Converts the ASCII index into its associated string representation.
 * @param index ASCII index
 * @return string representation of password
 */
string index_to_password(long long index) {
    if (index == 0)
        return string{1, '\0'};
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
    if (msg.type == Message::FOUND) {
        password_found = true;
        correct_password = index_to_password(msg.Found_Data->pwd_idx);
        cout << "Password Found by client: " << client_socket << ":" << correct_password << endl;
    }
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
 * Get the hashing algorithm based on the prescript.
 * @param pwd_hash The hashed password
 * @return The Hashing Algorithm
 */
const char *get_hash_type(const char *pwd_hash) {
    if (strncmp(pwd_hash, "$1$", 3) == 0) return "MD5";
    if (strncmp(pwd_hash, "$5$", 3) == 0) return "SHA-256";
    if (strncmp(pwd_hash, "$6$", 3) == 0) return "SHA-512";
    if (strncmp(pwd_hash, "$y$", 3) == 0) return "YESCRYPT";
    if (strncmp(pwd_hash, "$2a$", 3) == 0 || strncmp(pwd_hash, "$2b$", 3) == 0 || strncmp(pwd_hash, "$2y$", 3) == 0)
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
    if (strcmp(get_hash_type(hashed_pwd), "BCRYPT") == 0)
        ptr += 22;
    size_t salt_len = ptr - hashed_pwd;
    if (salt_len >= buffer_size) {
        salt_len = buffer_size - 1;
    }
    strncpy(salt_buffer, hashed_pwd, salt_len);
    salt_buffer[salt_len] = '\0';
}

void handle_message(int client_sock, long long work_size) {
    Message msg;
    if (!recv_message(client_sock, msg)) {
        lock_guard<mutex> lock(global_mutex);
        if (active_nodes.count(client_sock)) {
            reassign_remaining_work(client_sock);
        }
        close(client_sock);
        node_last_seen.erase(client_sock);
        checkpoints.erase(client_sock);
        active_nodes.erase(client_sock);
        FD_CLR(client_sock, &read_fds);
        return;
    }
    node_last_seen[client_sock] = chrono::steady_clock::now();
    if (password_found) {
        for (auto& [client_id, client_info] : active_nodes) {
            Message stop_msg(Message::STOP);
            send_message(client_id, stop_msg);
            cout << "Shutting down Node: " << client_id << endl;
        }
        return;
    }
    if (msg.type == Message::REQUEST) {
        static unordered_map<int, bool> setup_done;
        if (!setup_done[client_sock]) {
            Message setup(Message::SETUP, Message::Setup{client_sock, checkpoint, hashed_password, salt});
            send_message(client_sock, setup);
            setup_done[client_sock] = true;
        }
        pair<long long, long long> range;
        {
            lock_guard<mutex> lock(global_mutex);
            if (!checkpoints[-1].empty()) {
                range = checkpoints[-1].back();
                checkpoints[-1].pop_back();
            } else {
                range = get_range(next_range_start, work_size);
                next_range_start.fetch_add(work_size);
            }
            active_nodes[client_sock] = range;
        }
        cout << "REQUEST from Node: " << client_sock << endl;
        Message assign(Message::ASSIGN, Message::Assign{client_sock, range});
        send_message(client_sock, assign);
        cout << "Range: " << range.first << "-" << range.second << endl;
    } else if (msg.type == Message::FOUND) {
        password_found = true;
        correct_password = index_to_password(msg.Found_Data->pwd_idx);
        cout << "Password found: " << correct_password << " by Node: "
             << msg.Found_Data->node_id << endl;
    } else if (msg.type == Message::CHECKPOINT) {
        lock_guard<mutex> lock(global_mutex);
        checkpoints[client_sock] = msg.Checkpoint_Data->ranges;
        cout << "Node: " << client_sock << " Checkpoints: " << endl;
        for(auto &range: msg.Checkpoint_Data->ranges)
            cout << range.first << "-" << range.second << endl;
        send_message(client_sock, Message(Message::CONTINUE));
    }
}

void start_server(int port, long long work_size, int timeout_seconds) {
    int serv_sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (serv_sock < 0) {
        cerr << "Socket creation failed.\n";
        exit(1);
    }
    int opt = 0;
    setsockopt(serv_sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof (opt));
    sockaddr_in6 server_addr{};
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(port);
    server_addr.sin6_addr = in6addr_any;
    if (bind(serv_sock, (sockaddr *)&server_addr, sizeof (server_addr)) < 0) {
        cerr << "Bind failed.\n";
        exit(1);
    }

    listen(serv_sock, MAX_CLIENTS);
    FD_ZERO(&read_fds);
    FD_SET(serv_sock, &read_fds);
    int max_fd = serv_sock;
    cout << "Server started on port: " << port << endl;
    while(!password_found) {
        fd_set temp_fds = read_fds;
        timeval tv{.tv_sec = timeout_seconds, .tv_usec = 0};
        int activity = select(max_fd + 1, &temp_fds, nullptr, nullptr, &tv);
        if (activity < 0) continue;

        for (int fd = 0; fd <= max_fd; ++fd) {
            if (!FD_ISSET(fd, &temp_fds)) continue;
            if (fd == serv_sock) {
                sockaddr_in6 client_addr{};
                socklen_t client_size = sizeof(client_addr);
                int client_sock = accept(serv_sock, (sockaddr *)&client_addr, &client_size);
                if (client_sock < 0) continue;
                FD_SET(client_sock, &read_fds);
                if (client_sock > max_fd) max_fd = client_sock;
                cout << "New client connected. Node id: " << client_sock << endl;
            } else {
                handle_message(fd, work_size);
            }
        }
        // Handle disconnections (timeouts)
        auto now = chrono::steady_clock::now();
        lock_guard<mutex> lock(global_mutex);
        for (auto it = node_last_seen.begin(); it != node_last_seen.end();) {
            int node_id = it->first;
            auto last_seen = it->second;
            if (chrono::duration_cast<chrono::seconds>(now - last_seen).count() > timeout_seconds) {
                cerr << "Node: " << node_id << " timed out\n";
                reassign_remaining_work(node_id);
                close(node_id);
                FD_CLR(node_id, &read_fds);  // Remove from FD_SET
                checkpoints.erase(node_id);
                active_nodes.erase(node_id);
                node_last_seen.erase(++it);
            } else {
                ++it;
            }
        }
    }
    cout << "Password Found." << endl;
    // Send STOP message to all clients
    for (int fd = 0; fd <= max_fd; ++fd) {
        if (FD_ISSET(fd, &read_fds) && fd != serv_sock) {
            send_message(fd, Message(Message::STOP));
            close(fd);
        }
    }
    close(serv_sock);
}

void reassign_remaining_work(int client_sock) {
    if (!active_nodes.count(client_sock)) return;

    auto lost_range = active_nodes[client_sock];
    long long start = lost_range.first;
    long long end = lost_range.second;

    vector<pair<long long, long long>> completed_ranges;
    if (checkpoints.count(client_sock)) {
        completed_ranges = checkpoints[client_sock];
    }
    sort(completed_ranges.begin(), completed_ranges.end());

    vector<pair<long long, long long>> remaining;

    long long current_start = start;
    for (const auto& [chp_start, chp_end] : completed_ranges) {
        if (chp_start > current_start) {
            remaining.emplace_back(current_start, chp_start - 1);
        }
        current_start = max(current_start, chp_end + 1);
    }
    if (current_start <= end)
        remaining.emplace_back(current_start, end);

    for(const auto &r : remaining){
        checkpoints[-1].push_back(r);
        cout << "Reassigning range: " << r.first << "-" << r.second
             << " from node " << client_sock << endl;
    }
    active_nodes.erase(client_sock);
    checkpoints.erase(client_sock);
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        cerr << "Usage: " << argv[0] << " <port> <hash> <work-size> <checkpoint> <timeout>\n";
        return 1;
    }

    int port = stoi(argv[1]);
    char *hash = argv[2];
    long long work_size = stoll(argv[3]);
    checkpoint = stoi(argv[4]);
    int timeout = stoi(argv[5]);
    extract_salt(hash, salt, sizeof (salt));
    strcpy(hashed_password, hash);
    start_server(port, work_size, timeout);
    return 0;
}

