//
// Created by waleed on 26/03/25.
//

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <atomic>

using namespace std;

char* PASSWORD_TRIES = {};
string hashed_password, salt;
long long start_ascii, end_ascii;

atomic<bool> password_found(false);

void divide_work() {

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
    inet_pton(AF_INET6, server_ip.c_str(), &server_addr.sin6_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) <= 0) {
        cerr << "Connection failed with " + server_ip + " on port: " + to_string(server_port);
    }

    cout << "Connected to server: " << server_ip << " on port: " << server_port << endl;
    char buffer[12];
    if (recv(sock, buffer, sizeof (buffer), 0) != -1) {
        cout << "Received Data: " << endl;
        cout << buffer << endl;
    }

    if (send(sock, "REQUEST", 7, 0) == -1) {
        perror("Send Failed");
        exit(1);
    }



}



int main(int argc, char *argv[]){
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


    return 0;
}


