//
// Created by waleed on 26/03/25.
//

#ifndef MESSAGE_H
#define MESSAGE_H

#include <iostream>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <optional>

using namespace std;

class Message {
public:
    enum MessageType {
        REQUEST,    // From node to controller to get work assigned.
        ASSIGN,     // From controller to node to assign work range.
        CHECKPOINT, // From node to controller upon reaching checkpoint.
        FOUND,      // From node to controller upon finding password.
        DONE,       // From node to controller once work has finished.
        STOP,       // From controller to node to stop nodes once password's been found
                    // upon receiving checkpoint.
        CONTINUE,   // From controller to node upon receiving checkpoint
                    // but password hasn't been found.
        DEFAULT
    };

    struct Assign {
        int node_id;
        pair <long long, long long> range;

        string serialize() const;
        static Assign deserialize(const string &data);
    };

    /**
     * Checkpoint data: From Nodes to the controller.
     */
    struct Checkpoint {
        int node_id;
        vector<pair <long long, long long>> ranges;

        string serialize() const;
        static Checkpoint deserialize(const string &data);
    };

    struct Found {
        int node_id;
        long long pwd_idx;

        string  serialize() const;
        static Found deserialize(const string &data);
    };

    /**
     * Type of the message
     */
    MessageType type;

    // Optional Properties for the Message Class to simplify communication.
    optional<Assign> Assign_Data; // Server -> Node : To assign data range to work on.
    optional<Checkpoint> Checkpoint_Data; // Node -> Server : For Nodes to checkpoint their progress.
    optional<Found> Found_Data;

    explicit Message(MessageType type);
    Message();
    Message(MessageType type, const Assign &Assign_Data);
    Message(MessageType type, const Checkpoint &Checkpoint_Data);
    Message(MessageType type, const Found &Found_Data);

    //TODO Implement the serialization with optionals in mind.
    [[nodiscard]] string serialize() const;
    static Message deserialize(const string &data);


};

#endif //MESSAGE_H
