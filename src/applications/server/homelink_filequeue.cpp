#include <homelink_filequeue.h>

#include <homelink_security.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

static const std::string FILESYSTEM_ROOT =
    std::string(getenv("HOMELINK_ROOT")) + "/filesystem";

static std::mutex fileQueueLock;

std::string getTimestamp()
{
    static uint64_t counter = 1;

    int32_t tag = 0;
    randomBytes(reinterpret_cast<uint8_t *>(&tag), sizeof(tag));

    std::time_t now =
        std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    std::tm *utcTime = std::gmtime(&now);

    std::ostringstream ss;
    ss << std::put_time(utcTime, std::string("%Y-%m-%d__%Hh%Mm%Ss@" + std::to_string(counter++) + "|").c_str());
    ss << tag;
    return ss.str();
}

static std::vector<std::string> splitString(const std::string &s, char delim)
{
    std::string temp;
    std::vector<std::string> v;

    for (char c : s)
    {
        if (c == delim)
        {
            if (temp.size() != 0)
            {
                v.push_back(temp);
                temp.clear();
            }
        }
        else
        {
            temp.push_back(c);
        }
    }

    if (temp.size() != 0)
    {
        v.push_back(temp);
    }

    return v;
}

FileQueue::FileQueue()
{
    fs::create_directories(std::string(getenv("HOMELINK_ROOT")) + "/temp_files");
}

FileQueue *FileQueue::getInstance()
{
    static FileQueue instance;
    return &instance;
}

std::string FileQueue::nextFile(const std::string &hostId,
                                const std::string &serviceId)
{

    fs::path serviceRoot = FILESYSTEM_ROOT + "/" + hostId + "/" + serviceId;

    std::vector<fs::path> files;
    std::vector<std::string> stack;
    std::string ans = "";
    std::string timestamp = "";
    fileQueueLock.lock();
    if (fs::exists(serviceRoot) && fs::is_directory(serviceRoot))
    {
        for (const auto &entry : fs::directory_iterator(serviceRoot))
        {
            if (entry.is_regular_file())
            {
                ans = entry.path().string();
                break;
            }
        }
    }
    fileQueueLock.unlock();
    return ans;
}

void FileQueue::pullFile(const std::string &filePath)
{
    fileQueueLock.lock();
    fs::remove(filePath);
    fileQueueLock.unlock();
}

bool FileQueue::pushFile(const std::string &hostId,
                         const std::string &serviceId,
                         const std::string &path,
                         int32_t *tag)
{
    std::vector<std::string> tokens = splitString(path, '/');
    if (tokens.empty())
    {
        return false;
    }

    std::string filename;
    bool reading = false;
    for (char c : tokens.back())
    {
        if (reading)
        {
            filename.push_back(c);
        }
        else if (c == '.')
        {
            reading = true;
        }
    }

    std::ostringstream ss;
    ss << FILESYSTEM_ROOT;
    ss << "/" << hostId + "/" + serviceId;
    ss << "/";

    std::string directory = ss.str();

    fileQueueLock.lock();

    std::string timestamp = getTimestamp();
    ss << timestamp;
    ss << ".";
    ss << filename;

    fs::create_directories(directory);
    fs::rename(path, ss.str());

    fileQueueLock.unlock();

    if (tag != NULL)
    {
        int i = 0;
        for (; i < (int)timestamp.length(); ++i)
        {
            if (timestamp[i] == '|')
            {
                *tag = static_cast<int32_t>(atoll(timestamp.c_str() + i + 1));
                break;
            }
        }
    }

    return true;
}
