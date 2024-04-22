#include <homelink_filequeue.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

static const std::string FILESYSTEM_ROOT = std::string(getenv("HOMELINK_ROOT")) + "/filesystem";

std::string getTimestamp()
{

    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    std::tm *utcTime = std::gmtime(&now);

    std::ostringstream ss;
    ss << std::put_time(utcTime, "%Y-%m-%d__%Hh%Mm%Ss");
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
    fs::create_directory(std::string(getenv("HOMELINK_ROOT")) + "/temp");
}

std::string FileQueue::nextFile(const std::string &hostId, const std::string &serviceId)
{
    fs::path serviceRoot = FILESYSTEM_ROOT + "/" + hostId + "/" + serviceId;

    std::vector<fs::path> files;
    std::vector<std::string> stack;
    std::string ans = "";
    std::string timestamp = "";

    if (fs::exists(serviceRoot) && fs::is_directory(serviceRoot))
    {
        for (const auto &entry : fs::directory_iterator(serviceRoot))
        {
            if (entry.is_regular_file())
            {
                return entry.path().string();
            }
        }
    }
    return ans;
}

void FileQueue::pullFile(const std::string &filePath)
{
    fs::remove(filePath);
}

bool FileQueue::pushFile(const std::string &hostId, const std::string &serviceId, const std::string &path)
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

    std::string directory = ss.str();

    ss << "/";
    ss << getTimestamp();
    ss << ".";
    ss << filename;

    fs::create_directories(directory);

    fs::rename(path, ss.str());
    return true;
}
