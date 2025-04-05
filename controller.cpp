//
// Created by waleed on 04/04/25.
//

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <atomic>
#include <vector>
#include <mutex>
#include <unordered_map>
#include "Message.h"
#include <algorithm>
#include <cstring>

using namespace std;

#define MAX_CLIENTS FD_SETSIZE

string  correct_password;
vector<int> node_sockets; //Tracks the ids for the nodes.
atomic<bool> password_found(false);
mutex  global_mutex;

static atomic<long long> next_range_start(0);

unordered_map<int, pair<long long, long long>> active_nodes;
unordered_map<int, chrono::steady_clock::time_point> node_last_seen;
unordered_map<int, vector<pair<long long, long long>>> checkpoints;
char hashed_password[256], salt[64];
long long checkpoint;

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



