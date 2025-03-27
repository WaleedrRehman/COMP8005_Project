#include <iostream>
#include <chrono>
#include <cstring>
#include <crypt.h>
#include <omp.h>
#include <fstream>

using namespace std;

const string PYTHON_SCRIPT = "python3 /home/waleed/COMP8005/COMP8005_Assign_3/hashtester.py";


/**
 * Password Generator based on Generator template.
 * Generates 3 letter password guesses.
 * Tests common words and their combinations before passing through the rest of the ASCII char set.
 */
class PasswordGen {
private:
    // The most common characters in order.
    static constexpr char common_chars[] = "etaoinshrdlcumwfgypbvkjxqzETAOINSHRDLCUMWFGYPBVKJXQZ0123456789!@#$%^&*";
    static constexpr size_t common_size = sizeof(common_chars) - 1;
    bool tested_chars[256] = {false};
    bool common_phase = true; // Flag to determine whether common chars are being used currently.
    size_t i{}, j{}, k{}; // Track idx in iterations for combinations.
    char c1{}, c2{}, c3{}; // Selected chars.
    omp_lock_t lock{};

public:
    PasswordGen() {
        for (size_t x = 0; x < common_size; x++) {
            tested_chars[(unsigned char) common_chars[x]] = true;
        }
        reset(); // Resets the char indexes for the loop.
        omp_init_lock(&lock);
    }

    // Destructor to ensure that memory is freed.
    ~PasswordGen() {
        omp_destroy_lock(&lock);
    }

    void reset() {
        i = j = k = 0;
        c1 = c2 = c3 = 32;
    }

    /**
     * Guesser function.
     * @return
     */
    bool next_guess(char *guess) {
        omp_set_lock(&lock);

        if (common_phase) {
            if (i < common_size && j < common_size && k < common_size) {
                guess[0] = common_chars[i];
                guess[1] = common_chars[j];
                guess[2] = common_chars[k];

                if (++k == common_size) {
                    k = 0;
                    if (++j == common_size) {
                        j = 0;
                        ++i;
                    }
                }
                omp_unset_lock(&lock);
                return true;
            }
            common_phase = false;
        }

        while (c1 <= 128) {
            while (c2 <= 128) {
                while (c3 <= 128) {
                    if (!tested_chars[(unsigned char) c1] ||
                        !tested_chars[(unsigned char) c2] ||
                        !tested_chars[(unsigned char) c3]) {

                        guess[0] = c1;
                        guess[1] = c2;
                        guess[2] = c3;

                        c3++;
                        omp_unset_lock(&lock);
                        return true;
                    }
                    c3++;
                }
                c3 = 32;
                c2++;
            }
            c2 = 32;
            c1++;
        }
        omp_unset_lock(&lock);
        return false;
    }
};

/**
 * Gets the hash type of the given hashed password.
 */
const char *get_hash_type(const char *hashed_password) {
    if (strncmp(hashed_password, "$1$", 3) == 0) return "MD5";
    if (strncmp(hashed_password, "$5$", 3) == 0) return "SHA-256";
    if (strncmp(hashed_password, "$6$", 3) == 0) return "SHA-512";
    if (strncmp(hashed_password, "$y$", 3) == 0) return "YESCRYPT";
    if (strncmp(hashed_password, "$2a$", 3) == 0 ||
        strncmp(hashed_password, "$2b$", 3) == 0 ||
        strncmp(hashed_password, "$2y$", 3) == 0)
        return "BCRYPT";
    return "Unknown";
}


/**
 * Extracts the salt from a given hashed password.
 */
const char *extract_salt(const char *&hashed_password, char *salt_buffer) {
    size_t dollar_count = 0;
    const char *ptr = hashed_password;

    while (*ptr && dollar_count < 3) {
        if (*ptr == '$') dollar_count++;
        ptr++;
    }

    if (dollar_count < 3) return nullptr;

    // BCRYPT salt must include 22 chars after the 3rd dollar sign.
    if (strcmp(get_hash_type(hashed_password), "BCRYPT") == 0) {
        ptr += 22;
    }

    size_t salt_len = ptr - hashed_password;
    strncpy(salt_buffer, hashed_password, salt_len);
    salt_buffer[salt_len] = '\0';

    return salt_buffer;
}

/**
 * Uses the thread safe version of the PasswordGen to ensure that guesses
 * are generated only once ie threads aren't duplicating the guesses.
 * The
 *
 */
void brute_force_attack_passwordgen(const char *hashed_password) {
    PasswordGen generator;
    char salt[64];

    if (!extract_salt(hashed_password, salt)) {
        cerr << "Error extracting salt\n";
        return;
    }
//    cout << "Salt: " << salt << endl;
    bool found = false;
    long long global_loop_ct = 0;
    auto start = chrono::high_resolution_clock::now();

#pragma omp parallel // Multiple threads as input into the cmd arguments.
    {
        struct crypt_data crypt_buffer{};
        crypt_buffer.initialized = 0;
        char guess[4];

        while (!found && generator.next_guess(guess)) {
#pragma omp atomic
            global_loop_ct++;

            const char *generated_hash = crypt_r(guess, salt, &crypt_buffer);
            if (strcmp(generated_hash, hashed_password) == 0) {
                if (!found) {
#pragma omp critical
                    found = true;
                    cout << "Password found: " << guess << " in " << global_loop_ct << " attempts.\n";
                }
                break;
            }
        }
    }
    if (!found) {
        cout << "Password not found.\n";
    }
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::seconds>(end - start);
    cout << "Time taken to crack: " << duration.count() << " seconds" << endl;
}

void execute_python_script(const string &password) {
    string command = PYTHON_SCRIPT + " " + password + " > hashes.txt";
    system(command.c_str());
}

void brute_force_attack_password(const char *hashed_password, int num_threads) {
    char salt[64];

}


int main(int argc, char *argv[]) {

    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <Hashed Password> <num_threads>\n";
        return 1;
    }

//    string password = argv[1];
    int num_threads = stoi(argv[1]);
    if (num_threads < 1) {
        cerr << "Error: At least 1 thread needed to run. \n";
        return 1;
    }

    omp_set_num_threads(num_threads);

//    cout << "Generating hashes for password: " << password << "...\n";
//    execute_python_script(password);

    ifstream hash_file("hashes.txt");
    if (!hash_file) {
        cerr << "Error: Could not open hashes.txt\n";
        return 1;
    }


//    string line;
//    int line_count = 0;
//    while (getline(hash_file, line)) {
//        if (++line_count <= 3) continue; // Skip header lines
//
//        size_t pos = line.find_last_of(':');
//        if (pos != string::npos) {
//            string hash_value = line.substr(pos + 1); // Extract after `:`
//
//            // Trim leading spaces
//            size_t start = hash_value.find_first_not_of(" ");
//            if (start != string::npos) {
//                hash_value = hash_value.substr(start);
//            }
//
//            cout << "Extracted hash: '" << hash_value << "'" << endl; // Debug output
//            brute_force_attack_passwordgen(hash_value.c_str());
//        }
//    }


    cout << "Using " << num_threads << " threads for a brute force attack.\n";
    const char *test_hash = "$2b$05$lebCuLCIDyZ8pRx7f3.Gj.L8bdOpxeZZPUsIzCmgoq4MV3SGlQVQK";
    const char *hash_type = get_hash_type(test_hash);
    cout << "Hash Type: " << hash_type << endl;
    brute_force_attack_passwordgen(test_hash);

    return 0;
}
