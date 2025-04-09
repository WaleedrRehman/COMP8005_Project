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

// Global Data
string  correct_password;
atomic<bool> password_found(false);
mutex  global_mutex;

// Node Tracking
unordered_map<int, pair<long long, long long>> active_nodes;
unordered_map<int, chrono::steady_clock::time_point> node_last_seen;
unordered_map<int, vector<pair<long long, long long>>> checkpoints;
vector<pair<long long, long long>> remaining_work;

// Password Information
char hashed_password[256], salt[64];
long long checkpoint_interval;
static atomic<long long> next_range_start(0);

// Network State
fd_set read_fds;

void reassign_remaining_work(int client_sock);
void handle_found(int node_id, long long pwd_idx);
void handle_checkpoint(int node_id, const Message::Checkpoint& msg);
void assign_work(int node_id, long long work_size);

vector<string> messages_text{"REQUEST", "ASSIGN", "CHECKPOINT", "FOUND", "STOP", "CONTINUE"};


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
        reassign_remaining_work(client_sock);
        active_nodes.erase(client_sock);
        checkpoints.erase(client_sock);
        node_last_seen.erase(client_sock);
        FD_CLR(client_sock, &read_fds);
        close(client_sock);
        return;
    }
        node_last_seen[client_sock] = chrono::steady_clock::now();

        switch (msg.type) {
            case Message::REQUEST:
                assign_work(client_sock, work_size);
                break;

            case Message::CHECKPOINT:
                if (msg.Checkpoint_Data)
                    handle_checkpoint(client_sock, *msg.Checkpoint_Data);
                break;

            case Message::FOUND:
                if (msg.Found_Data)
                    handle_found(client_sock, msg.Found_Data->pwd_idx);
                break;

            default:
                cout << "Unknown " << msg.type << " type from " << client_sock << endl;

    }


}

void handle_checkpoint(int node_id, const Message::Checkpoint& msg) {
    lock_guard<mutex> lock(global_mutex);

    checkpoints[node_id] = msg.ranges;
    node_last_seen[node_id] = chrono::steady_clock::now();
    cout << "Checkpoint from Node: " << node_id << endl;
    for (auto& range : msg.ranges) {
        cout << "[" << range.first << "-" << range.second << "]" << endl;
    }
    if (password_found.load()) {
        send_message(node_id, Message(Message::STOP));
    } else {
        send_message(node_id, Message(Message::CONTINUE));
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

    auto og_range = active_nodes[client_sock];
    auto node_checkpoints = checkpoints[client_sock];

    long long cur = og_range.first;

    sort(node_checkpoints.begin(), node_checkpoints.end());
    for (const auto& [chp_start, chp_end] : node_checkpoints) {
        if (chp_start > cur) {
            remaining_work.emplace_back(cur, chp_start - 1);
        }
        cur = max(cur, chp_end + 1);
    }
    if (cur <= og_range.second) {
        remaining_work.emplace_back(cur, og_range.second);
    }

    lock_guard<mutex> lock(global_mutex);
    for (auto &range : remaining_work) {
        next_range_start = min(next_range_start.load(), range.first);
        cout << "Reassigning range: " << range.first << "-" << range.second << endl;
    }
}

void handle_found(int node_id, long long pwd_idx) {
    lock_guard<mutex> lock(global_mutex);

    if (!password_found.exchange(true)) {
        correct_password = index_to_password(pwd_idx);
        cout << "PASSWORD FOUND BY NODE " << node_id << ": " << correct_password << endl;

        // Send STOP to all other nodes
        for (auto& [id, _] : active_nodes) {
            if (id != node_id) {
                send_message(id, Message(Message::STOP));
            }
        }
    }
}

void assign_work(int node_id, long long work_size) {
    lock_guard<mutex> lock(global_mutex);

    // Assign new range
    long long start = next_range_start.fetch_add(work_size);
    pair<long long, long long> range = {start, start + work_size - 1};

    active_nodes[node_id] = range;
    node_last_seen[node_id] = chrono::steady_clock::now();

    Message assign(Message::ASSIGN, Message::Assign{node_id, checkpoint_interval ,range, hashed_password, salt});
    send_message(node_id, assign);

    cout << "Assigned " << node_id << ": " << range.first << "-" << range.second << endl;
}

void stop_all() {
    lock_guard<mutex> lock(global_mutex);
    for(auto& [node_id, _] : active_nodes) {
        send_message(node_id, Message(Message::STOP));
    }
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        cerr << "Usage: " << argv[0] << " <port> <hash> <work-size> <checkpoint_interval> <timeout>\n";
        return 1;
    }

    int port = stoi(argv[1]);
    char *hash = argv[2];
    long long work_size = stoll(argv[3]);
    checkpoint_interval = stoi(argv[4]);
    int timeout = stoi(argv[5]);
    extract_salt(hash, salt, sizeof (salt));
    strcpy(hashed_password, hash);
    start_server(port, work_size, timeout);
    return 0;
}

