//
// Created by waleed on 26/03/25.
//
#include "Message.h"

/**
 * Default Constructor
 */
Message::Message() = default;

/**
 * Message with types other than ASSIGN or CHECKPOINT
 * @param type
 */
Message::Message(Message::MessageType type) {
    this->type = type;
}

/**
 *
 * @param type
 * @param Assign_Data
 */
Message::Message(Message::MessageType type, const Message::Assign &Assign_Data) {
    this->type = type;
    this->Assign_Data = Assign_Data;
}

/**
 * Message constructor for a Checkpoint message
 * @param type Message type ie a checkpoint
 * @param Checkpoint_Data Data for the Checkpoint ie range for the checkpoint.
 */
Message::Message(Message::MessageType type, const Message::Checkpoint &Checkpoint_Data) {
    this->type = type;
    this->Checkpoint_Data = Checkpoint_Data;
}

Message::Message(Message::MessageType type, const Message::Found &Found_Data) {
    this->type = type;
    this->Found_Data = Found_Data;
}

// ASSIGN SERIALIZATION and DESERIALIZATION

/**
 *
 * @return String representation of the Assign struct.
 */
string Message::Assign::serialize() const {
    return to_string(node_id) + "," + to_string(range.first) + "-" + to_string(range.second);
}

/**
 *
 * @param data
 * @return
 */
Message::Assign Message::Assign::deserialize(const std::string &data) {
    istringstream ss(data);
    int node_id;
    long long start, end;
    char delim;
    ss >> node_id >> delim >> start >> delim >> end;
    return {node_id, {start, end}};
}

// CHECKPOINT SERIALIZATION AND DESERIALIZATION

string  Message::Checkpoint::serialize() const {
    ostringstream ss;
    ss << node_id;
    for (const auto &r: ranges) {
        ss << ":" << r.first << "-" << r.second;
    }
    return ss.str();
}

/**
 * Deserializer for the
 * @param data
 * @return
 */
Message::Checkpoint Message::Checkpoint::deserialize(const std::string &data) {
    istringstream ss(data);
    int node_id;
    char delim;
    vector<pair<long long, long long>> ranges;

    ss >> node_id;
    string range_str;
    while (getline(ss, range_str, ':')) {
        size_t dash = range_str.find('-');
        if (dash != string::npos) {
            long long start = stoll(range_str.substr(0, dash));
            long long end = stoll(range_str.substr(dash + 1));
            ranges.emplace_back(start, end);
        }
    }
    return {node_id, ranges};
}

// FOUND SERIALIZATION AND DESERIALIZATION

string Message::Found::serialize() const {
    return to_string(node_id) + "," + to_string(pwd_idx);

}

Message::Found Message::Found::deserialize(const string &data) {
    istringstream ss(data);
    int node_id;
    long long pwd_idx;
    char delim;
    ss >> node_id >> delim >> pwd_idx;
    return {node_id, pwd_idx};
}


/**
 * Serialization -> Calls the appropriate serialization based on the struct.
 * @return serialized string
 */
string Message::serialize() const {
    ostringstream ss;
    ss << type;

    if (Assign_Data) {
        ss << "|" << Assign_Data->serialize();
    } else if (Checkpoint_Data) {
        ss << "|" << Checkpoint_Data->serialize();
    } else if (Found_Data) {
        ss << "|" << Found_Data->serialize();
    }

    return ss.str();
}

/**
 * Deserialization -> Calls the appropriate deserialization based on the struct.
 * @param data The data to be deserialized
 * @return Message Object
 */
Message Message::deserialize(const std::string &data) {
    size_t delim = data.find('|');
    MessageType type = static_cast<MessageType>(stoi(data.substr(0, delim)));
    string content = (delim != string::npos) ? data.substr(delim + 1) : "";

    if (type == ASSIGN) {
        return Message{type, Assign::deserialize(content)};
    } else if (type == CHECKPOINT) {
        return Message{type, Checkpoint::deserialize(content)};
    } else if (type == FOUND) {
        return Message{type, Found::deserialize(content)};
    } else {
        return Message{type};
    }
}






//vector<string> Message::split_content(const string &content, char delimiter) {
//    vector<string> parts;
//    stringstream  ss(content);
//    string  item;
//
//    while (getline(ss, item, delimiter)) {
//        parts.push_back(item);
//    }
//    return parts;
//}

int main() {
//    Message msg{Message::MessageType::DEFAULT};
//    cout << msg.serialize() << endl;
    Message assign(Message::FOUND, Message::Found{12, 1213221});
    string  serialized_assign = assign.serialize();
    cout << serialized_assign << endl;
    Message deserialized = Message::deserialize(serialized_assign);
    cout << deserialized.type << " " << deserialized.Found_Data->pwd_idx << endl;
}

