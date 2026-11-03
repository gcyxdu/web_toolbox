#ifndef SECCOM_TEE_TRUSTZONE_CA_COMMON_CONFIG_LOADER_HPP
#define SECCOM_TEE_TRUSTZONE_CA_COMMON_CONFIG_LOADER_HPP

#include <cstdlib>
#include <fstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

#include <limits.h>
#include <unistd.h>

namespace seccom {

inline std::string Trim(const std::string &value) {
    const std::string whitespace = " \t\r\n";
    const std::size_t start = value.find_first_not_of(whitespace);
    if (start == std::string::npos) {
        return "";
    }
    const std::size_t end = value.find_last_not_of(whitespace);
    return value.substr(start, end - start + 1);
}

inline std::string StripQuotes(const std::string &value) {
    if (value.size() >= 2) {
        const char first = value.front();
        const char last = value.back();
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            return value.substr(1, value.size() - 2);
        }
    }
    return value;
}

class FlatYamlConfig {
public:
    explicit FlatYamlConfig(std::unordered_map<std::string, std::string> values)
        : values_(std::move(values)) {}

    std::string Require(const std::string &key) const {
        const auto found = values_.find(key);
        if (found == values_.end() || found->second.empty()) {
            throw std::runtime_error("missing config key: " + key);
        }
        return found->second;
    }

    std::string Get(const std::string &key, const std::string &fallback) const {
        const auto found = values_.find(key);
        if (found == values_.end() || found->second.empty()) {
            return fallback;
        }
        return found->second;
    }

    int GetInt(const std::string &key, int fallback) const {
        const auto found = values_.find(key);
        if (found == values_.end() || found->second.empty()) {
            return fallback;
        }
        return std::atoi(found->second.c_str());
    }

    std::size_t GetSizeT(const std::string &key, std::size_t fallback) const {
        const auto found = values_.find(key);
        if (found == values_.end() || found->second.empty()) {
            return fallback;
        }
        return static_cast<std::size_t>(std::strtoull(found->second.c_str(), nullptr, 10));
    }

private:
    std::unordered_map<std::string, std::string> values_;
};

inline FlatYamlConfig LoadFlatYamlFile(const std::string &path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        throw std::runtime_error("failed to open config file: " + path);
    }

    std::unordered_map<std::string, std::string> values;
    std::string line;
    while (std::getline(input, line)) {
        const std::string trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#') {
            continue;
        }

        const std::size_t separator = trimmed.find(':');
        if (separator == std::string::npos) {
            continue;
        }

        const std::string key = Trim(trimmed.substr(0, separator));
        std::string value = Trim(trimmed.substr(separator + 1));
        const std::size_t comment = value.find(" #");
        if (comment != std::string::npos) {
            value = Trim(value.substr(0, comment));
        }
        values[key] = StripQuotes(value);
    }

    return FlatYamlConfig(std::move(values));
}

inline std::string GetExecutableDir() {
    char buffer[PATH_MAX] = {0};
    const ssize_t length = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (length <= 0) {
        throw std::runtime_error("failed to resolve executable path");
    }
    buffer[length] = '\0';

    const std::string executable_path(buffer);
    const std::size_t slash = executable_path.find_last_of('/');
    if (slash == std::string::npos) {
        return ".";
    }
    return executable_path.substr(0, slash);
}

inline std::string JoinPath(const std::string &dir, const std::string &name) {
    if (dir.empty() || dir == ".") {
        return name;
    }
    if (dir.back() == '/') {
        return dir + name;
    }
    return dir + "/" + name;
}

}  // namespace seccom

#endif
