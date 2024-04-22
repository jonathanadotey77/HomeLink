#ifndef HOMELINK_FILEQUEUE_H
#define HOMELINK_FILEQUEUE_H

#include <string>

class FileQueue
{
private:
public:
    FileQueue();

    std::string nextFile(const std::string &hostId, const std::string &serviceId);
    void pullFile(const std::string &filePath);
    bool pushFile(const std::string &hostId, const std::string &serviceId, const std::string &path);
};

std::string getTimestamp();

#endif
