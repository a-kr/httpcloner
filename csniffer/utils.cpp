#include <vector>
#include <string>
#include <sstream>
#include <unistd.h>

std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}


std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
}

std::string gethostname() {
    char buf[201];
    if (gethostname(buf, 200) != 0) {
        perror("gethostname");
        return std::string("unknown");
    }
    return std::string(buf);
}

