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
string correct_password;
atomic<bool> password_found(false);
mutex global_mutex;

// Node Tracking
unordered_map<int, pair<long long, long long>> active_nodes;
unordered_map<int, chrono::steady_clock::time_point> node_last_seen;
unordered_map<int, vector<pair<long long, long long>>> checkpoints;
vector<pair<long long, long long>> remaining_work;
chrono::steady_clock::time_point server_start_time;

// Password Information
char hashed_password[256], salt[64];
long long checkpoint_interval;
static atomic<long long> next_range_start(0);

// Network State
fd_set read_fds;

void reassign_remaining_work(int client_sock);
void handle_found(int node_id, long long pwd_idx);
void assign_work(int node_id, long long work_size);
vector<string> messages_text{"REQUEST", "ASSIGN", "CHECKPOINT", "FOUND", "STOP", "CONTINUE"};
constexpr int ASCII_RANGE = 256;

pair<long long, long long> get_range(long long start_idx, long long size) {
    return {start_idx, start_idx + size - 1};
}

string index_to_password(long long index) {
    string password;
    while (index || password.empty()) {
        password.insert(password.begin(), static_cast<char>(index % ASCII_RANGE));
        index /= ASCII_RANGE;
    }
    return password;
}

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

void send_message(int client_socket, const Message &msg) {
    string serialized = msg.serialize();
    uint32_t size = serialized.size();
    send(client_socket, &size, sizeof(size), 0);
    send(client_socket, serialized.c_str(), serialized.size(), 0);
}

const char *get_hash_type(const char *pwd_hash) {
    if (strncmp(pwd_hash, "$1$", 3) == 0) return "MD5";
    if (strncmp(pwd_hash, "$5$", 3) == 0) return "SHA-256";
    if (strncmp(pwd_hash, "$6$", 3) == 0) return "SHA-512";
    if (strncmp(pwd_hash, "$y$", 3) == 0) return "YESCRYPT";
    if (strncmp(pwd_hash, "$2a$", 3) == 0 || strncmp(pwd_hash, "$2b$", 3) == 0 || strncmp(pwd_hash, "$2y$", 3) == 0)
        return "BCRYPT";
    return "Unknown";
}

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
    node_last_seen[client_sock] = chrono::steady_clock::now();
    if (!recv_message(client_sock, msg)) {
        lock_guard<mutex> lock(global_mutex);
        reassign_remaining_work(client_sock);
        active_nodes.erase(client_sock);
        node_last_seen.erase(client_sock);
        FD_CLR(client_sock, &read_fds);
        close(client_sock);
        return;
    }
    cout << "Handling message from node: " << client_sock << ": " + messages_text[msg.type] << endl;
    switch (msg.type) {
        case Message::REQUEST:
            if (password_found.load()) {
                send_message(client_sock, Message{Message::STOP});
            } else {
                assign_work(client_sock, work_size);
            }
            break;
        case Message::FOUND:
            if (msg.Found_Data)
                handle_found(client_sock, msg.Found_Data->pwd_idx);
            break;
        default:
            cout << "Unknown " << msg.type << " type from " << client_sock << endl;
    }
}
void start_server(int port, long long work_size, int timeout_seconds) {
    int serv_sock = socket(AF_INET6, SOCK_STREAM, 0);
    if (serv_sock < 0) {
        cerr << "Socket creation failed.\n";
        exit(1);
    }
    int opt = 0;
    setsockopt(serv_sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
    sockaddr_in6 server_addr{};
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(port);
    server_addr.sin6_addr = in6addr_any;
    if (bind(serv_sock, (sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        cerr << "Bind failed.\n";
        exit(1);
    }

    listen(serv_sock, MAX_CLIENTS);
    FD_ZERO(&read_fds);
    FD_SET(serv_sock, &read_fds);
    int max_fd = serv_sock;
    cout << "Server started on port: " << port << endl;
    while (!password_found) {
        fd_set temp_fds = read_fds;
        timeval tv{.tv_sec = timeout_seconds, .tv_usec = 0};
        int activity = select(max_fd + 1, &temp_fds, nullptr, nullptr, &tv);
        if (activity < 0) continue;

        for (int fd = 0; fd <= max_fd; ++fd) {
            if (!FD_ISSET(fd, &temp_fds)) continue;
            if (fd == serv_sock) {
                sockaddr_in6 client_addr{};
                socklen_t client_size = sizeof(client_addr);
                int client_sock = accept(serv_sock, (sockaddr *) &client_addr, &client_size);
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
            cout << "Node: " << node_id << " last seen at: "
                 << chrono::duration_cast<chrono::seconds>(last_seen.time_since_epoch()).count() << endl;
            if (chrono::duration_cast<chrono::seconds>(now - last_seen).count() > timeout_seconds) {
                cerr << "Node: " << node_id << " timed out\n";
                close(node_id);
                FD_CLR(node_id, &read_fds);  // Remove from FD_SET
                reassign_remaining_work(node_id);
                active_nodes.erase(node_id);
                node_last_seen.erase(it);
            } else {
                ++it;
            }
        }
    }
    auto end_time = chrono::steady_clock::now();
    auto duration = chrono::duration_cast<chrono::seconds>(end_time - server_start_time).count();
    cout << "Time taken to crack password: " << duration << " seconds." << endl;
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
    if (active_nodes.count(client_sock)) {
        remaining_work.push_back(active_nodes[client_sock]);
    }
}

void handle_found(int node_id, long long pwd_idx) {
    lock_guard<mutex> lock(global_mutex);
    if (!password_found.exchange(true)) {
        correct_password = index_to_password(pwd_idx);
        cout << "PASSWORD FOUND BY NODE " << node_id << ": " << correct_password << endl;
    }
}

void assign_work(int node_id, long long work_size) {
    pair<long long, long long> range;
    if (!remaining_work.empty()) {
        range = remaining_work.back();
        remaining_work.pop_back();
        cout << "Reassigning range from remaining work: "
             << range.first << "-" << range.second << endl;
    } else {
        long long start = next_range_start.fetch_add(work_size);
        range = {start, start + work_size - 1};
        cout << "Assigning new range: " << range.first << "-" << range.second << endl;
    }
    // Assign new range
    active_nodes[node_id] = range;
    node_last_seen[node_id] = std::chrono::steady_clock::now();

    Message assign(Message::ASSIGN, Message::Assign{node_id, checkpoint_interval, range, hashed_password, salt});
    send_message(node_id, assign);
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
    extract_salt(hash, salt, sizeof(salt));
    strcpy(hashed_password, hash);
    server_start_time = chrono::steady_clock::now();
    start_server(port, work_size, timeout);
    return 0;
}

