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
 * Message Constructor for controller
 * @param type
 * @param Assign_Data
 */
Message::Message(Message::MessageType type, const Message::Assign &Assign_Data) {
    this->type = type;
    this->Assign_Data = Assign_Data;
}

/**
 * Message constructor for a Checkpoint message
 * @param type Message type ie a checkpoint_interval
 * @param Checkpoint_Data Data for the Checkpoint ie range for the checkpoint_interval.
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
 * Assign Data
 * @return String representation of the Assign struct.
 */
string Message::Assign::serialize() const {
    string result;
    result.reserve(64 + hashed_password.size() + salt.size());
    result.append(to_string(node_id)).append(",")
          .append(to_string(checkpoint)).append(",")
          .append(to_string(range.first)).append("-")
          .append(to_string(range.second)).append(",")
          .append(hashed_password).append(",")
          .append(salt);
    return result;
}

/**
 *
 * @param data
 * @return
 */
Message::Assign Message::Assign::deserialize(const std::string &data) {
    size_t pos1 = data.find(',');
    size_t pos2 = data.find(',', pos1 + 1);
    size_t pos3 = data.find(',', pos2 + 1);
    size_t pos4 = data.find(',', pos3 + 1);

    int node_id = stoi(data.substr(0, pos1));
    long long checkpoint = stoll(data.substr(pos1 + 1, pos2 - pos1 - 1));
    string range_str = data.substr(pos2 + 1, pos3 - pos2 - 1);
    size_t dash = range_str.find('-');
    long long start = stoll(range_str.substr(0, dash));
    long long end = stoll(range_str.substr(dash + 1));

    string hashed_password = data.substr(pos3 + 1, pos4 - pos3 -1);
    string  salt = data.substr(pos4 + 1);

    return {node_id, checkpoint, {start, end}, hashed_password, salt};
}

// CHECKPOINT SERIALIZATION AND DESERIALIZATION

/**
 *
 * @return
 */
string  Message::Checkpoint::serialize() const {
    string result;
    result.reserve(16 + ranges.size() * 24);
    result.append(to_string(node_id));
    for (const auto &r : ranges) {
        result.append(":").append(to_string(r.first)).append("-").append(to_string(r.second));
    }
    return result;
}

/**
 * Deserializer for the
 * @param data
 * @return
 */
Message::Checkpoint Message::Checkpoint::deserialize(const std::string &data) {
    size_t colon = data.find(':');
    int node_id = stoi(data.substr(0, colon));

    vector<pair<long long, long long>> ranges;
    size_t start = colon + 1, end;

    while ((end = data.find(':', start)) != string::npos) {
        size_t dash = data.find('-', start);
        long long r1 = stoll(data.substr(start, dash - start));
        long long r2 = stoll(data.substr(dash + 1, end - dash - 1));
        ranges.emplace_back(r1, r2);
        start = end + 1;
    }

    if (start < data.length()) {
        size_t dash = data.find('-', start);
        long long r1 = stoll(data.substr(start, dash - start));
        long long r2 = stoll(data.substr(dash + 1));
        ranges.emplace_back(r1, r2);
    }

    return {node_id, ranges};
}

// FOUND SERIALIZATION AND DESERIALIZATION

string Message::Found::serialize() const {
    return to_string(node_id) + "," + to_string(pwd_idx);

}

Message::Found Message::Found::deserialize(const string &data) {
    size_t delim = data.find(',');
    int node_id = stoi(data.substr(0, delim));
    long long pwd_idx = stoll(data.substr(delim + 1));
    return {node_id, pwd_idx};
}

/**
 * Serialization -> Calls the appropriate serialization based on the type.
 * @return serialized string
 */
string Message::serialize() const {
    string result = to_string(type);

    if (Assign_Data) {
        result.append("|").append(Assign_Data->serialize());
    } else if (Checkpoint_Data) {
        result.append("|").append(Checkpoint_Data->serialize());
    } else if (Found_Data) {
        result.append("|").append(Found_Data->serialize());
    }

    return result;
}

/**
 * Deserialization -> Calls the appropriate deserialization based on the type.
 * @param data The data to be deserialized
 * @return Message Object
 */
Message Message::deserialize(const std::string &data) {
    size_t delim = data.find('|');
    MessageType type = static_cast<MessageType>(stoi(data.substr(0, delim)));
    string content = (delim != string::npos) ? data.substr(delim + 1) : "";

    switch (type) {
        case ASSIGN: return Message{type, Assign::deserialize(content)};
        case CHECKPOINT: return Message{type, Checkpoint::deserialize(content)};
        case FOUND: return Message{type, Found::deserialize(content)};
        default: return Message{type};
    }
}



//int main() {
////    Message msg{Message::MessageType::DEFAULT};
////    cout << msg.serialize() << endl;
//    Message assign(Message::ASSIGN, Message::Assign{12, 21231 , {1231,2313}, "Hash", "Salt"});
//    string  serialized_assign = assign.serialize();
//    cout << serialized_assign << endl;
//    Message deserialized = Message::deserialize(serialized_assign);
//    cout << " Type: " << deserialized.type << " Node Id: " << deserialized.Assign_Data->node_id
//    << " Ranges: " << deserialized.Assign_Data->range.first << "-"
//    << deserialized.Assign_Data->range.second << " Hash: " << endl;
//}

