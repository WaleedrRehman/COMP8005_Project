//
// Created by waleed on 26/03/25.
//

#include <iostream>
#include <sys/socket.h>


using namespace std;

char* PASSWORD_TRIES = {};

void worker_main();

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


    int sock = socket(AF_INET6, SOCK_STREAM, 0);




    return 0;
}
