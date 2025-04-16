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
int worker_socket;
mutex mtx;

vector<string> messages_text{"REQUEST", "ASSIGN", "CHECKPOINT", "FOUND", "STOP", "CONTINUE"};
long long start_range, end_range;
atomic<bool> password_found(false);

long long pwd_idx;

vector<pair<long long, long long>> thread_ranges;
constexpr int PRINTABLE_RANGE = 71;
constexpr int BASE_ASCII = 60;

bool divide_work(int num_threads, const string& hashed_password, const string& salt, long long total_start, long long total_end);

bool recv_message(int client_socket, Message &msg) {
    uint32_t net_size;
    ssize_t recvd = recv(client_socket, &net_size, sizeof(net_size), MSG_WAITALL);
    if (recvd <= 0) {
        cerr << "Failed to receive message size or client disconnected.\n";
        return false;
    }
    uint32_t size = ntohl(net_size);
    string buffer(size, '\0');
    size_t total_received = 0;
    while (total_received < size) {
        ssize_t r = recv(client_socket, buffer.data() + total_received, size - total_received, 0);
        if (r <= 0) {
            cerr << "Failed to receive full message.\n";
            return false;
        }
        total_received += r;
    }
    try {
        msg = Message::deserialize(buffer);
    } catch (const exception &e) {
        cerr << "Deserialization failed: " << e.what() << "\n";
        return false;
    }
    return true;
}

void send_message(int client_socket, const Message &msg) {
    string serialized = msg.serialize();
    uint32_t size = htonl(static_cast<uint32_t>(serialized.size()));
    if (send(client_socket, &size, sizeof(size), 0) != sizeof(size)) {
        cerr << "Failed to send message size.\n";
        return;
    }
    const char *data = serialized.c_str();
    size_t total_sent = 0;
    size_t total_size = serialized.size();
    while (total_sent < total_size) {
        ssize_t sent = send(client_socket, data + total_sent, total_size - total_sent, 0);
        if (sent <= 0) {
            cerr << "Failed to send full message.\n";
            return;
        }
        total_sent += sent;
    }
}

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

bool request_work(int num_threads, string& hashed_password, string& salt) {
    cout << "Requesting Work from Controller" << endl;
    Message request_msg(Message::REQUEST);
    send_message(worker_socket, request_msg);
    Message resp;
    bool received = recv_message(worker_socket, resp);
    cout << messages_text[resp.type] << endl;

    if (received && resp.type == Message::ASSIGN && resp.Assign_Data) {
        start_range = resp.Assign_Data->range.first;
        end_range = resp.Assign_Data->range.second;
        hashed_password = resp.Assign_Data->hashed_password;
        salt = resp.Assign_Data->salt;
        cout << "Range received: " << start_range << "-" << end_range << endl;
        divide_work(num_threads, hashed_password, salt, start_range, end_range);
        return true;
    } else if (received && resp.type == Message::STOP) {
        cout << "[!] Received STOP from server. Exiting..." << endl;
        password_found.store(true);
        return false;
    }
    return false;
}

void crack_password(int thread_id, long long start, long long end,
                    const string &hashed_password, const string &salt) {
    thread_local struct crypt_data crypt_buffer{};
    crypt_buffer.initialized = 0;
    char pwd_guess[256];
    size_t target_hash_len = hashed_password.length();
    const char *hashed_pwd = hashed_password.c_str();
    const char *pwd_salt = salt.c_str();
    bool found = false;
    for (long long i = start; i <= end && !found; ++i) {
        if (i % 1000 == 0) {
            found = password_found.load();
            if (found)
                break;
        }
        long long idx = i;
        size_t len = 0;
        while (idx || len == 0) {
            pwd_guess[len++] = static_cast<char>((idx % PRINTABLE_RANGE) + BASE_ASCII);
            idx /= PRINTABLE_RANGE;
        }
        pwd_guess[len] = '\0';
        const char *gen_hash = crypt_r(pwd_guess, pwd_salt, &crypt_buffer);
        if (!gen_hash) {
            cerr << "Error: crypt_r() failed for password: " << pwd_guess << endl;
            continue;
        }
        size_t gen_hash_len = strlen(gen_hash);
        if (gen_hash_len == target_hash_len &&
            memcmp(gen_hash, hashed_pwd, gen_hash_len) == 0) {

            lock_guard<mutex> lock(mtx);
            if (!password_found.exchange(true)) {
                cout << "[+] Password found by thread " << thread_id << ": " << pwd_guess << endl;
                pwd_idx = i;

                // Send FOUND message to server
                Message found_msg(Message::FOUND);
                found_msg.Found_Data = Message::Found{worker_socket, pwd_idx};
                send_message(worker_socket, found_msg);
            }
            return;
        }
    }
}


bool divide_work(int num_threads, const string& hashed_password, const string& salt,
                 long long total_start, long long total_end) {
    cout << "Dividing work across " << num_threads << " threads." << endl;
    thread_ranges.resize(num_threads);
    long long range_size = (total_end - total_start + 1) / num_threads;
    vector<thread> threads;
    threads.reserve(num_threads);
    for (int i = 0; i < num_threads; ++i) {
        long long start = total_start + i * range_size;
        long long end = (i == num_threads - 1) ? total_end : start + range_size - 1;
        thread_ranges[i] = {start, end};
        threads.emplace_back(crack_password, i, start, end, hashed_password, salt);
        cout << "Thread: " << i + 1 << ",Range: " << thread_ranges[i].first << "-" << thread_ranges[i].second << endl;
    }
    for (auto& t : threads) {
        if (t.joinable()) t.detach();
    }
    return password_found.load();
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
        cerr << "Error: At least 1 thread needed to run.\n";
        return 1;
    }

    cout << "Server IP: " << server_ip << endl;
    cout << "Server Port: " << server_port << endl;
    cout << "Number of Threads: " << num_threads << endl;

    string hashed_password, salt;
    start_conn(server_ip, server_port);

    bool stop_received = false;

    while (!stop_received) {
        if (password_found.load()) {
            cout << "Password Found. Waiting for server to send STOP...\n";

            Message maybe_stop;
            while (true) {
                if (recv_message(worker_socket, maybe_stop)) {
                    if (maybe_stop.type == Message::STOP) {
                        cout << "[✓] Received STOP from server. Shutting down...\n";
                        stop_received = true;
                        break;  // Exit inner loop
                    } else {
                        cout << "[*] Received message: " << messages_text[maybe_stop.type] << endl;
                    }
                } else {
                    cerr << "[!] Error or disconnect while waiting for STOP. Retrying...\n";
                    this_thread::sleep_for(chrono::seconds(2));
                }
            }
            continue;  // Check stop_received in outer loop
        }

        if (!request_work(num_threads, hashed_password, salt)) {
            cout << "[*] No work assigned. Retrying...\n";
            this_thread::sleep_for(chrono::seconds(1));
            continue;
        }

        if (!password_found.load()) {
            cout << "[*] Batch complete. Requesting more work...\n";
            this_thread::sleep_for(chrono::milliseconds(100));
            continue;
        }
    }

    close(worker_socket);
    return 0;
}



