#ifndef HOMELINK_FILEQUEUE_H
#define HOMELINK_FILEQUEUE_H

#include <string>

// SINGLETON
class FileQueue
{
private:
    FileQueue();

    // Deleted copy constructor and assignment operator.
    FileQueue(const FileQueue &other) = delete;
    FileQueue &operator=(const FileQueue &other) = delete;

public:
    // Returns Singleton instance.
    static FileQueue *getInstance();

    // Returns the path to the next file in the service's queue,
    // or an empty string if the queue is empty.
    std::string nextFile(const std::string &hostId, const std::string &serviceId);

    // Removes a the first file in the service's queue.
    void pullFile(const std::string &filePath);

    // Adds a file to the service's queue.
    bool pushFile(const std::string &hostId, const std::string &serviceId,
                  const std::string &path);
};

// Returns the current timestamp, in the format "%Y-%m-%d__%Hh%Mm%Ss"
std::string getTimestamp();

#endif
