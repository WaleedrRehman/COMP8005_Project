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
atomic<bool> shutdown_requested(false);

// Node Tracking
unordered_map<int, pair<long long, long long>> active_nodes;
unordered_map<int, chrono::steady_clock::time_point> node_last_seen;
vector<pair<long long, long long>> remaining_work;
chrono::steady_clock::time_point server_start_time;

// Password Information
char hashed_password[256], salt[64];
long long checkpoint_interval;
static atomic<long long> next_range_start(0);

// Network State
fd_set read_fds;
int max_fd, serv_sock;

void reassign_remaining_work(int client_sock);
void handle_found(int node_id, long long pwd_idx);
void assign_work(int node_id, long long work_size);
vector<string> messages_text{"REQUEST", "ASSIGN", "CHECKPOINT", "FOUND", "STOP", "CONTINUE"};
constexpr int PRINTABLE_RANGE = 95;
constexpr int BASE_ASCII = 32;
chrono::steady_clock::time_point first_node_connection_time;

void signal_handler(int signum) {
    cout << "\nSignal (" << signum << ") received. Shutting down..." << endl;
    shutdown_requested.store(true);
}

string index_to_password(long long index) {
    string password;
    while (index || password.empty()) {
        password.insert(password.begin(), static_cast<char>((index % PRINTABLE_RANGE) + BASE_ASCII));
        index /= PRINTABLE_RANGE;
    }
    return password;
}
bool recv_message(int client_socket, Message &msg) {
    uint32_t size_net;
    ssize_t n = recv(client_socket, &size_net, sizeof(size_net), MSG_WAITALL);

    if (n == 0) {
        cout << "\nNode: " << client_socket << " disconnected gracefully.\n" << endl;
        return false;
    } else if (n < 0) {
        cerr << "[recv_message] Error receiving message size: " << strerror(errno) << endl;
        return false;
    } else if (n != sizeof(size_net)) {
        cerr << "[recv_message] Incomplete size read: " << n << " bytes." << endl;
        return false;
    }

    uint32_t size = ntohl(size_net);
    if (size == 0 || size > 10 * 1024 * 1024) {
        cerr << "[recv_message] Invalid message size: " << size << endl;
        return false;
    }

    string buffer(size, '\0');
    n = recv(client_socket, buffer.data(), size, MSG_WAITALL);

    if (n == 0) {
        cerr << "[recv_message] Node: " << client_socket << "disconnected during payload receive." << endl;
        return false;
    } else if (n < 0) {
        cerr << "[recv_message] Error receiving message payload: " << strerror(errno) << endl;
        return false;
    } else if (n != size) {
        cerr << "[recv_message] Incomplete message payload received: " << n << " of " << size << " bytes." << endl;
        return false;
    }

    try {
        msg = Message::deserialize(buffer);
    } catch (const std::exception &e) {
        cerr << "[recv_message] Deserialization error: " << e.what() << endl;
//        return false;
    }



    return true;
}


bool send_message(int client_socket, const Message &msg) {
    string serialized = msg.serialize();
    uint32_t size = serialized.size();
    uint32_t size_net = htonl(size);
    if (send(client_socket, &size_net, sizeof(size_net), 0) != sizeof(size_net)) {
        cerr << "[send_message] Failed to send message size." << endl;
        return false;
    }
    ssize_t total_sent = 0;
    const char *data = serialized.c_str();
    while (total_sent < size) {
        ssize_t sent = send(client_socket, data + total_sent, size - total_sent, 0);
        if (sent <= 0) {
            cerr << "[send_message] Failed to send full message payload." << endl;
            return false;
        }
        total_sent += sent;
    }
    return true;
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
    serv_sock = socket(AF_INET6, SOCK_STREAM, 0);
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
    max_fd = serv_sock;
    cout << "Server started on port: " << port << endl;

    while (!password_found && !shutdown_requested.load()) {
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

                // Track the time of the first client connection
                if (first_node_connection_time == chrono::steady_clock::time_point()) {
                    first_node_connection_time = chrono::steady_clock::now();
                }
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
//    auto end_time = chrono::steady_clock::now();
//    auto duration = chrono::duration_cast<chrono::seconds>(end_time - server_start_time).count();
//    if (password_found.load()) {
//        cout << "Time taken to crack password: " << duration << " seconds." << endl;
//        cout << "Password Found." << endl;
//    }
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

        // Calculate time difference between the first node connection and password found
        auto end_time = chrono::steady_clock::now();
        auto duration = chrono::duration_cast<chrono::seconds>(end_time - first_node_connection_time).count();
        cout << "Time taken to find password after first node connected: " << duration << " seconds." << endl;

        // Send a STOP message to the client that found the password
        Message stop_msg(Message::STOP);
        send_message(node_id, stop_msg);

        // Optionally, add a brief delay before shutting down the connection

        // Close the connection gracefully
        close(node_id);
        FD_CLR(node_id, &read_fds);

        // Send STOP message to all other clients
        for (int fd = 0; fd <= max_fd; ++fd) {
            if (FD_ISSET(fd, &read_fds) && fd != serv_sock) {
                send_message(fd, Message(Message::STOP));
                close(fd);
            }
        }
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
        cerr << "Usage: " << argv[0] << " --port --hash --work-size --checkpoint_interval --timeout\n";
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

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

