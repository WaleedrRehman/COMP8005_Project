//
// Created by waleed on 26/03/25.
//
#include <iostream>
#include <sstream>
#include <vector>

using namespace std;

class Message {
public:
    enum MessageType {
        REQUEST,
        ASSIGN,
        CHECKPOINT,
        FOUND,
        DONE,
        STOP
    };

    MessageType type;
    string content;

    Message(MessageType type, const string &content) {
        this->type = type;
        this->content = content;
    }

    string serialize() const {
        return to_string(type) + ":" + content;
    }

    static Message deserialize(const string &data) {
        size_t pos = data.find(':');
        if (pos == string::npos) {
            throw invalid_argument("Message Format Invalid");
        }

        int msg_type = stoi(data.substr(0, pos));
        string  msg_content = data.substr(pos + 1);

        return Message {static_cast<MessageType>(msg_type), msg_content};
    }

    static vector<string> split_content(const string &content, char delimiter) {
        vector<string> parts;
        stringstream  ss(content);
        string  item;

        while (getline(ss, item, delimiter)) {
            parts.push_back(item);
        }
        return parts;
    }
};