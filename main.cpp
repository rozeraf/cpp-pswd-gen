#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <regex>
#include <map>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <set>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <cerrno>
#include <cstring>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <openssl/rand.h>

#ifndef DICEWARE_WORDLIST_PATH
#define DICEWARE_WORDLIST_PATH "data/eff_large_wordlist.txt"
#endif

class SecureRandom {
public:
    std::uint64_t uniform(std::uint64_t upper_exclusive) const {
        if (upper_exclusive == 0) {
            throw std::invalid_argument("Random range must not be empty");
        }

        std::uint64_t value;
        const std::uint64_t limit = std::numeric_limits<std::uint64_t>::max()
                                  - (std::numeric_limits<std::uint64_t>::max() % upper_exclusive);
        do {
            if (RAND_priv_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) != 1) {
                throw std::runtime_error("OpenSSL CSPRNG failed");
            }
        } while (value >= limit);
        return value % upper_exclusive;
    }

    template <typename T>
    void shuffle(std::vector<T>& values) const {
        for (std::size_t i = values.size(); i > 1; --i) {
            std::swap(values[i - 1], values[uniform(i)]);
        }
    }
};

class PasswordGenerator {
private:
    std::string lowercase = "abcdefghijklmnopqrstuvwxyz";
    std::string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string digits = "0123456789";
    std::string special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    std::string ambiguous_chars = "il1Lo0O";

    std::vector<std::string> diceware_words;
    SecureRandom rng;

    void loadDicewareWords() {
        std::vector<std::filesystem::path> candidates = {
            DICEWARE_WORDLIST_PATH,
            std::filesystem::path("data") / "eff_large_wordlist.txt"
        };

        std::ifstream file;
        for (const auto& path : candidates) {
            file.open(path);
            if (file) break;
            file.clear();
        }
        if (!file) {
            throw std::runtime_error("EFF Diceware wordlist not found");
        }

        std::string dice_code;
        std::string word;
        while (file >> dice_code >> word) {
            diceware_words.push_back(word);
        }
        if (diceware_words.size() != 7776) {
            throw std::runtime_error("Invalid EFF Diceware wordlist (expected 7776 entries)");
        }
    }

public:
    PasswordGenerator() { loadDicewareWords(); }

    // Component structures for custom password builder
    struct Component {
        enum Type {
            TEXT,
            WORD,
            RANDOM_CHARS,
            NUMBER,
            SEPARATOR
        };

        Type type;
        std::string value;
        std::map<std::string, std::string> config;
        std::vector<std::string> options;

        Component(Type t) : type(t) {}
    };

    std::string getRandomWord(int min_length = 3, int max_length = 10) {
        std::vector<std::string> suitable_words;
        const auto min_size = static_cast<std::size_t>(std::max(0, min_length));
        const auto max_size = static_cast<std::size_t>(std::max(0, max_length));
        for (const auto& word : diceware_words) {
            if (word.length() >= min_size && word.length() <= max_size) {
                suitable_words.push_back(word);
            }
        }

        if (suitable_words.empty()) {
            suitable_words = diceware_words;
        }

        return suitable_words[rng.uniform(suitable_words.size())];
    }

    std::string removeAmbiguous(const std::string& chars) {
        std::string result;
        for (char c : chars) {
            if (ambiguous_chars.find(c) == std::string::npos) {
                result += c;
            }
        }
        return result;
    }

    std::string generatePassword(int length = 12, bool use_uppercase = true,
                                bool use_lowercase = true, bool use_digits = true,
                                bool use_special = true, bool exclude_ambiguous = false,
                                int min_uppercase = 1, int min_lowercase = 1,
                                int min_digits = 1, int min_special = 1) {
        if (length < 4) {
            throw std::invalid_argument("Password too short");
        }

        std::string char_pool;
        std::vector<char> required_chars;

        if (use_lowercase) {
            std::string chars = exclude_ambiguous ? removeAmbiguous(lowercase) : lowercase;
            char_pool += chars;
            for (int i = 0; i < min_lowercase; i++) {
                required_chars.push_back(chars[rng.uniform(chars.size())]);
            }
        }

        if (use_uppercase) {
            std::string chars = exclude_ambiguous ? removeAmbiguous(uppercase) : uppercase;
            char_pool += chars;
            for (int i = 0; i < min_uppercase; i++) {
                required_chars.push_back(chars[rng.uniform(chars.size())]);
            }
        }

        if (use_digits) {
            std::string chars = exclude_ambiguous ? removeAmbiguous(digits) : digits;
            char_pool += chars;
            for (int i = 0; i < min_digits; i++) {
                required_chars.push_back(chars[rng.uniform(chars.size())]);
            }
        }

        if (use_special) {
            char_pool += special_chars;
            for (int i = 0; i < min_special; i++) {
                required_chars.push_back(special_chars[rng.uniform(special_chars.size())]);
            }
        }

        if (char_pool.empty()) {
            throw std::invalid_argument("No character types selected");
        }

        if (required_chars.size() > static_cast<std::size_t>(length)) {
            throw std::invalid_argument("Requirements exceed password length");
        }

        int remaining_length = length - required_chars.size();
        for (int i = 0; i < remaining_length; i++) {
            required_chars.push_back(char_pool[rng.uniform(char_pool.size())]);
        }

        rng.shuffle(required_chars);
        return std::string(required_chars.begin(), required_chars.end());
    }

    std::string generateMemorablePassword(int num_words = 6, const std::string& separator = "-",
                                         bool add_numbers = true, bool capitalize = true,
                                         int word_min_length = 3, int word_max_length = 8) {
        std::vector<std::string> selected_words;
        for (int i = 0; i < num_words; i++) {
            std::string word = getRandomWord(word_min_length, word_max_length);
            if (capitalize && !word.empty()) {
                word[0] = std::toupper(word[0]);
            }
            selected_words.push_back(word);
        }

        std::string password;
        for (size_t i = 0; i < selected_words.size(); i++) {
            password += selected_words[i];
            if (i < selected_words.size() - 1) {
                password += separator;
            }
        }

        if (add_numbers) {
            std::ostringstream oss;
            oss << std::setfill('0') << std::setw(3) << rng.uniform(1000);
            password += oss.str();
        }

        return password;
    }

    std::string generateComplexMemorablePassword(int num_words = 3, bool add_special_chars = true,
                                               bool add_numbers = true, bool transform_words = true,
                                               int min_length = 16) {
        std::vector<std::string> words;
        for (int i = 0; i < num_words; i++) {
            std::string word = getRandomWord(4, 8);

            if (transform_words) {
                int transform_type = static_cast<int>(rng.uniform(4));

                switch (transform_type) {
                    case 0:
                        if (!word.empty()) word[0] = std::toupper(word[0]);
                        break;
                    case 1:
                        std::transform(word.begin(), word.end(), word.begin(), ::toupper);
                        break;
                    case 2:
                        std::transform(word.begin(), word.end(), word.begin(), ::tolower);
                        break;
                    case 3:
                        if (word.length() > 4) {
                            if (!word.empty()) word[0] = std::toupper(word[0]);
                        } else {
                            std::transform(word.begin(), word.end(), word.begin(), ::toupper);
                        }
                        break;
                }

                if (rng.uniform(3) == 0) {
                    std::map<char, char> replacements = {
                        {'a', '4'}, {'e', '3'}, {'i', '1'}, {'o', '0'}, {'s', '5'}, {'t', '7'}
                    };

                    for (auto& pair : replacements) {
                        if (rng.uniform(2) == 0) {
                            std::replace(word.begin(), word.end(), pair.first, pair.second);
                            std::replace(word.begin(), word.end(), static_cast<char>(std::toupper(pair.first)), pair.second);
                            break;
                        }
                    }
                }
            }

            words.push_back(word);
        }

        std::vector<std::string> separators = {"", "-", "_", ".", "!", "@", "#"};
        std::string password;

        for (size_t i = 0; i < words.size(); i++) {
            password += words[i];
            if (i < words.size() - 1) {
                if (add_special_chars) {
                    if (rng.uniform(2) == 0) {
                        password += separators[3 + rng.uniform(separators.size() - 3)];
                    } else {
                        password += separators[rng.uniform(3)];
                    }
                } else {
                    password += separators[rng.uniform(separators.size())];
                }
            }
        }

        if (add_numbers) {
            std::vector<std::string> positions = {"start", "middle", "end"};
            std::string position = positions[rng.uniform(positions.size())];

            std::ostringstream oss;
            oss << std::setfill('0') << std::setw(2) << rng.uniform(10000);
            std::string number = oss.str();

            if (position == "start") {
                password = number + password;
            } else if (position == "end") {
                password = password + number;
            } else {
                int mid = password.length() / 2;
                password.insert(mid, number);
            }
        }

        while (password.length() < static_cast<std::size_t>(min_length) && add_special_chars) {
            std::string special_chars_subset = "!@#$%^&*";
            char special_char = special_chars_subset[rng.uniform(special_chars_subset.size())];
            std::size_t position = rng.uniform(password.size() + 1);
            password.insert(position, 1, special_char);
        }

        return password;
    }

    // NEW: Custom password builder function
    std::string buildCustomPassword(const std::vector<Component>& components) {
        std::string password;

        for (const auto& component : components) {
            switch (component.type) {
                case Component::TEXT: {
                    password += component.value;
                    break;
                }

                case Component::WORD: {
                    int min_length = 3, max_length = 10;
                    bool capitalize = false, uppercase = false, lowercase = false, random_case = false;
                    std::map<char, char> replacements;

                    // Parse config
                    auto it = component.config.find("min_length");
                    if (it != component.config.end()) {
                        min_length = std::stoi(it->second);
                    }

                    it = component.config.find("max_length");
                    if (it != component.config.end()) {
                        max_length = std::stoi(it->second);
                    }

                    it = component.config.find("capitalize");
                    if (it != component.config.end()) {
                        capitalize = (it->second == "true");
                    }

                    it = component.config.find("uppercase");
                    if (it != component.config.end()) {
                        uppercase = (it->second == "true");
                    }

                    it = component.config.find("lowercase");
                    if (it != component.config.end()) {
                        lowercase = (it->second == "true");
                    }

                    it = component.config.find("random_case");
                    if (it != component.config.end()) {
                        random_case = (it->second == "true");
                    }

                    it = component.config.find("replacements");
                    if (it != component.config.end() && it->second == "true") {
                        replacements = {{'a', '4'}, {'e', '3'}, {'i', '1'}, {'o', '0'}, {'s', '5'}};
                    }

                    std::string word = getRandomWord(min_length, max_length);

                    // Apply transformations
                    if (capitalize && !word.empty()) {
                        word[0] = std::toupper(word[0]);
                    } else if (uppercase) {
                        std::transform(word.begin(), word.end(), word.begin(), ::toupper);
                    } else if (lowercase) {
                        std::transform(word.begin(), word.end(), word.begin(), ::tolower);
                    } else if (random_case) {
                        for (char& c : word) {
                            c = rng.uniform(2) == 0 ? std::toupper(c) : std::tolower(c);
                        }
                    }

                    // Apply replacements
                    for (const auto& pair : replacements) {
                        std::replace(word.begin(), word.end(), pair.first, pair.second);
                    }

                    password += word;
                    break;
                }

                case Component::RANDOM_CHARS: {
                    int length = 4;
                    std::vector<std::string> types = {"lowercase", "uppercase", "digits"};

                    // Parse config
                    auto it = component.config.find("length");
                    if (it != component.config.end()) {
                        length = std::stoi(it->second);
                    }

                    it = component.config.find("types");
                    if (it != component.config.end()) {
                        types.clear();
                        std::istringstream iss(it->second);
                        std::string type;
                        while (std::getline(iss, type, ',')) {
                            types.push_back(type);
                        }
                    }

                    std::string char_pool;
                    for (const auto& type : types) {
                        if (type == "lowercase") {
                            char_pool += lowercase;
                        } else if (type == "uppercase") {
                            char_pool += uppercase;
                        } else if (type == "digits") {
                            char_pool += digits;
                        } else if (type == "special") {
                            char_pool += special_chars;
                        }
                    }

                    if (!char_pool.empty()) {
                        for (int i = 0; i < length; i++) {
                            password += char_pool[rng.uniform(char_pool.size())];
                        }
                    }
                    break;
                }

                case Component::NUMBER: {
                    int min_val = 0, max_val = 9999, padding = 0;

                    // Parse config
                    auto it = component.config.find("min");
                    if (it != component.config.end()) {
                        min_val = std::stoi(it->second);
                    }

                    it = component.config.find("max");
                    if (it != component.config.end()) {
                        max_val = std::stoi(it->second);
                    }

                    it = component.config.find("padding");
                    if (it != component.config.end()) {
                        padding = std::stoi(it->second);
                    }

                    int number = min_val + static_cast<int>(rng.uniform(
                        static_cast<std::uint64_t>(max_val) - min_val + 1));

                    std::ostringstream oss;
                    if (padding > 0) {
                        oss << std::setfill('0') << std::setw(padding);
                    }
                    oss << number;

                    password += oss.str();
                    break;
                }

                case Component::SEPARATOR: {
                    std::vector<std::string> separators = {"-", "_", ".", "!", "@", "#"};

                    if (!component.options.empty()) {
                        separators = component.options;
                    }

                    if (separators.empty()) {
                        throw std::invalid_argument("Separator list must not be empty");
                    }
                    password += separators[rng.uniform(separators.size())];
                    break;
                }
            }
        }

        return password;
    }

    std::string generatePasswordByComplexity(int complexity = 5) {
        if (complexity < 1 || complexity > 10) {
            throw std::invalid_argument("Complexity must be 1-10");
        }

        int length;
        bool use_uppercase, use_lowercase, use_digits, use_special, exclude_ambiguous;
        int min_uppercase, min_lowercase, min_digits, min_special;

        if (complexity <= 2) {
            length = 8 + complexity;
            use_uppercase = complexity >= 2;
            use_lowercase = true;
            use_digits = complexity >= 2;
            use_special = false;
            exclude_ambiguous = true;
            min_uppercase = use_uppercase ? 1 : 0;
            min_lowercase = 2;
            min_digits = use_digits ? 1 : 0;
            min_special = 0;
        } else if (complexity <= 4) {
            length = 10 + complexity;
            use_uppercase = true;
            use_lowercase = true;
            use_digits = true;
            use_special = complexity >= 4;
            exclude_ambiguous = complexity <= 3;
            min_uppercase = 1;
            min_lowercase = 2;
            min_digits = 1;
            min_special = use_special ? 1 : 0;
        } else if (complexity <= 6) {
            length = 12 + complexity;
            use_uppercase = true;
            use_lowercase = true;
            use_digits = true;
            use_special = true;
            exclude_ambiguous = false;
            min_uppercase = 2;
            min_lowercase = 2;
            min_digits = 2;
            min_special = 1;
        } else if (complexity <= 8) {
            length = 16 + (complexity - 6) * 2;
            use_uppercase = true;
            use_lowercase = true;
            use_digits = true;
            use_special = true;
            exclude_ambiguous = false;
            min_uppercase = 2;
            min_lowercase = 3;
            min_digits = 2;
            min_special = 2;
        } else {
            length = 20 + (complexity - 8) * 4;
            use_uppercase = true;
            use_lowercase = true;
            use_digits = true;
            use_special = true;
            exclude_ambiguous = false;
            min_uppercase = 3;
            min_lowercase = 4;
            min_digits = 3;
            min_special = 3;
        }

        return generatePassword(length, use_uppercase, use_lowercase, use_digits,
                              use_special, exclude_ambiguous, min_uppercase,
                              min_lowercase, min_digits, min_special);
    }

    std::string getComplexityDescription(int complexity) {
        std::map<int, std::string> descriptions = {
            {1, "Very Simple - lowercase only (9 chars)"},
            {2, "Simple - letters and digits (10 chars)"},
            {3, "Basic - letters and digits, no ambiguous (13 chars)"},
            {4, "Medium - all types, no ambiguous (14 chars)"},
            {5, "Good - all character types (17 chars)"},
            {6, "Strong - all types, more requirements (18 chars)"},
            {7, "Very Strong - increased length (18 chars)"},
            {8, "Excellent - high requirements (20 chars)"},
            {9, "Maximum - very long and complex (24 chars)"},
            {10, "Extreme - maximum protection (28 chars)"}
        };

        auto it = descriptions.find(complexity);
        return it != descriptions.end() ? it->second : "Unknown level";
    }

    struct PasswordAnalysis {
        int score;
        std::string strength;
        std::vector<std::string> feedback;
        int length;
        bool has_lowercase;
        bool has_uppercase;
        bool has_digits;
        bool has_special;
        int unique_chars;
    };

    PasswordAnalysis checkPasswordStrength(const std::string& password) {
        PasswordAnalysis analysis;
        analysis.score = 0;
        analysis.length = password.length();

        if (password.length() >= 16) {
            analysis.score += 3;
        } else if (password.length() >= 12) {
            analysis.score += 2;
        } else if (password.length() >= 8) {
            analysis.score += 1;
        } else {
            analysis.feedback.push_back("Too short");
        }

        analysis.has_lowercase = std::any_of(password.begin(), password.end(), ::islower);
        analysis.has_uppercase = std::any_of(password.begin(), password.end(), ::isupper);
        analysis.has_digits = std::any_of(password.begin(), password.end(), ::isdigit);
        analysis.has_special = std::any_of(password.begin(), password.end(),
            [this](char c) { return special_chars.find(c) != std::string::npos; });

        int char_types = analysis.has_lowercase + analysis.has_uppercase +
                        analysis.has_digits + analysis.has_special;
        analysis.score += char_types;

        if (char_types < 3) {
            analysis.feedback.push_back("Use different character types");
        }

        std::set<char> unique_set(password.begin(), password.end());
        analysis.unique_chars = unique_set.size();

        if (analysis.unique_chars >= password.length() * 0.8) {
            analysis.score += 2;
        } else if (analysis.unique_chars >= password.length() * 0.6) {
            analysis.score += 1;
        } else {
            analysis.feedback.push_back("Too many repeated characters");
        }

        std::vector<std::regex> patterns = {
            std::regex(R"((.)\1{2,})"),
            std::regex(R"((012|123|234|345|456|567|678|789|890))"),
            std::regex(R"((abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz))"),
            std::regex(R"((qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm))")
        };

        std::string lower_password = password;
        std::transform(lower_password.begin(), lower_password.end(), lower_password.begin(), ::tolower);

        bool pattern_found = false;
        for (const auto& pattern : patterns) {
            if (std::regex_search(lower_password, pattern)) {
                pattern_found = true;
                break;
            }
        }

        if (pattern_found) {
            analysis.score -= 2;
            analysis.feedback.push_back("Avoid simple sequences");
        }

        std::vector<std::string> common_passwords = {"password", "123456", "qwerty", "admin", "login", "welcome"};
        for (const auto& common : common_passwords) {
            if (lower_password.find(common) != std::string::npos) {
                analysis.score -= 3;
                analysis.feedback.push_back("Avoid common passwords");
                break;
            }
        }

        analysis.score = std::max(0, analysis.score);

        if (analysis.score >= 10) {
            analysis.strength = "Excellent";
        } else if (analysis.score >= 8) {
            analysis.strength = "Very Strong";
        } else if (analysis.score >= 6) {
            analysis.strength = "Strong";
        } else if (analysis.score >= 4) {
            analysis.strength = "Medium";
        } else if (analysis.score >= 2) {
            analysis.strength = "Weak";
        } else {
            analysis.strength = "Very Weak";
        }

        return analysis;
    }
};

class UserInterface {
private:
    PasswordGenerator gen;

    static void writePrivateFile(const std::string& path, const std::string& contents) {
#ifdef _WIN32
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file || !(file << contents)) {
            throw std::runtime_error("Cannot write " + path);
        }
#else
        int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
        if (fd < 0) {
            throw std::runtime_error("Cannot securely open " + path + ": " + std::strerror(errno));
        }
        if (::fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
            const int error = errno;
            ::close(fd);
            throw std::runtime_error("Cannot restrict permissions on " + path + ": " + std::strerror(error));
        }

        std::size_t written = 0;
        while (written < contents.size()) {
            const ssize_t result = ::write(fd, contents.data() + written, contents.size() - written);
            if (result < 0) {
                const int error = errno;
                ::close(fd);
                throw std::runtime_error("Cannot write " + path + ": " + std::strerror(error));
            }
            written += static_cast<std::size_t>(result);
        }
        if (::close(fd) != 0) {
            throw std::runtime_error("Cannot close " + path);
        }
#endif
    }

public:
    bool askYesNo(const std::string& prompt, bool default_value = true) {
        std::string default_text = default_value ? "y" : "n";
        std::string input;

        while (true) {
            std::cout << prompt << " (y/n, default " << default_text << "): ";
            std::getline(std::cin, input);

            if (input.empty()) {
                return default_value;
            }

            std::transform(input.begin(), input.end(), input.begin(), ::tolower);

            if (input == "y" || input == "yes") {
                return true;
            } else if (input == "n" || input == "no") {
                return false;
            } else {
                std::cout << "Please enter 'y' or 'n'\n";
            }
        }
    }

    int askNumber(const std::string& prompt, int min_val = 1, int max_val = 100, int default_val = -1) {
        std::string input;

        while (true) {
            if (default_val != -1) {
                std::cout << prompt << " (default " << default_val << "): ";
            } else {
                std::cout << prompt << ": ";
            }

            std::getline(std::cin, input);

            if (input.empty() && default_val != -1) {
                return default_val;
            }

            try {
                int value = std::stoi(input);
                if (value >= min_val && value <= max_val) {
                    return value;
                } else {
                    std::cout << "Value must be between " << min_val << " and " << max_val << "\n";
                }
            } catch (const std::exception&) {
                std::cout << "Please enter a valid number\n";
            }
        }
    }

    std::string askString(const std::string& prompt, const std::string& default_val = "") {
        std::string input;

        if (!default_val.empty()) {
            std::cout << prompt << " (default '" << default_val << "'): ";
        } else {
            std::cout << prompt << ": ";
        }

        std::getline(std::cin, input);

        return input.empty() && !default_val.empty() ? default_val : input;
    }

    void showMenu() {
        std::cout << "\n" << std::string(50, '=') << "\n";
        std::cout << "           PASSWORD GENERATOR\n";
        std::cout << std::string(50, '=') << "\n";
        std::cout << "1. Standard password\n";
        std::cout << "2. Memorable password\n";
        std::cout << "3. Complex memorable password\n";
        std::cout << "4. Custom password builder\n";
        std::cout << "5. Multiple passwords\n";
        std::cout << "6. Check password strength\n";
        std::cout << "7. Quick generation\n";
        std::cout << "8. Generate by complexity level\n";
        std::cout << "0. Exit\n";
        std::cout << std::string(50, '=') << "\n";
    }

    // NEW: Custom password builder interactive function
    void buildCustomPasswordInteractive() {
        std::cout << "\n--- CUSTOM PASSWORD BUILDER ---\n";
        std::cout << "Build a password from components of your choice!\n";
        std::cout << "\nAvailable component types:\n";
        std::cout << "1. Text (fixed string)\n";
        std::cout << "2. Random word\n";
        std::cout << "3. Random characters\n";
        std::cout << "4. Number\n";
        std::cout << "5. Separator\n";

        std::vector<PasswordGenerator::Component> components;

        while (true) {
            std::cout << "\n--- Component #" << (components.size() + 1) << " ---\n";
            std::cout << "Choose component type:\n";
            std::cout << "1. Text\n";
            std::cout << "2. Random word\n";
            std::cout << "3. Random characters\n";
            std::cout << "4. Number\n";
            std::cout << "5. Separator\n";
            std::cout << "6. Finish and create password\n";
            std::cout << "0. Cancel\n";

            int choice = askNumber("Your choice", 0, 6);

            if (choice == 0) {
                return;
            } else if (choice == 6) {
                break;
            } else if (choice == 1) {
                // Text component
                std::string text = askString("Enter text");
                if (!text.empty()) {
                    PasswordGenerator::Component comp(PasswordGenerator::Component::TEXT);
                    comp.value = text;
                    components.push_back(comp);
                }

            } else if (choice == 2) {
                // Random word component
                std::cout << "\nWord settings:\n";
                int min_len = askNumber("Minimum word length", 2, 15, 4);
                int max_len = askNumber("Maximum word length", min_len, 20, 8);

                std::cout << "\nTransformation:\n";
                std::cout << "1. No changes\n";
                std::cout << "2. Capitalize first letter\n";
                std::cout << "3. All uppercase\n";
                std::cout << "4. All lowercase\n";
                std::cout << "5. Random case\n";

                int transform = askNumber("Choose transformation", 1, 5, 2);

                PasswordGenerator::Component comp(PasswordGenerator::Component::WORD);
                comp.config["min_length"] = std::to_string(min_len);
                comp.config["max_length"] = std::to_string(max_len);
                comp.config["capitalize"] = (transform == 2) ? "true" : "false";
                comp.config["uppercase"] = (transform == 3) ? "true" : "false";
                comp.config["lowercase"] = (transform == 4) ? "true" : "false";
                comp.config["random_case"] = (transform == 5) ? "true" : "false";

                if (askYesNo("Add letter to number replacements (a->4, e->3, etc)?", false)) {
                    comp.config["replacements"] = "true";
                }

                components.push_back(comp);

            } else if (choice == 3) {
                // Random characters component
                int length = askNumber("Length", 1, 20, 4);

                std::cout << "\nCharacter types:\n";
                std::vector<std::string> types;
                if (askYesNo("Lowercase letters?", true)) {
                    types.push_back("lowercase");
                }
                if (askYesNo("Uppercase letters?", true)) {
                    types.push_back("uppercase");
                }
                if (askYesNo("Digits?", true)) {
                    types.push_back("digits");
                }
                if (askYesNo("Special characters?", false)) {
                    types.push_back("special");
                }

                if (!types.empty()) {
                    PasswordGenerator::Component comp(PasswordGenerator::Component::RANDOM_CHARS);
                    comp.config["length"] = std::to_string(length);

                    std::string types_str;
                    for (size_t i = 0; i < types.size(); i++) {
                        types_str += types[i];
                        if (i < types.size() - 1) types_str += ",";
                    }
                    comp.config["types"] = types_str;

                    components.push_back(comp);
                }

            } else if (choice == 4) {
                // Number component
                int min_val = askNumber("Minimum value", 0, 999999, 0);
                int max_val = askNumber("Maximum value", min_val, 999999, 999);
                int padding = askNumber("Pad with zeros to length (0 = no padding)", 0, 10, 0);

                PasswordGenerator::Component comp(PasswordGenerator::Component::NUMBER);
                comp.config["min"] = std::to_string(min_val);
                comp.config["max"] = std::to_string(max_val);
                comp.config["padding"] = std::to_string(padding);

                components.push_back(comp);

            } else if (choice == 5) {
                // Separator component
                std::cout << "\nChoose separator:\n";
                std::cout << "1. Hyphen (-)\n";
                std::cout << "2. Underscore (_)\n";
                std::cout << "3. Dot (.)\n";
                std::cout << "4. Exclamation (!)\n";
                std::cout << "5. At sign (@)\n";
                std::cout << "6. Hash (#)\n";
                std::cout << "7. Random from all\n";
                std::cout << "8. Custom\n";

                int sep_choice = askNumber("Choice", 1, 8, 7);

                PasswordGenerator::Component comp(PasswordGenerator::Component::SEPARATOR);

                if (sep_choice == 8) {
                    std::string custom_seps = askString("Enter possible separators (space-separated)");
                    std::istringstream iss(custom_seps);
                    std::string sep;
                    while (iss >> sep) {
                        comp.options.push_back(sep);
                    }
                } else {
                    std::vector<std::vector<std::string>> sep_options = {
                        {"-"}, {"_"}, {"."}, {"!"}, {"@"}, {"#"},
                        {"-", "_", ".", "!", "@", "#"}
                    };
                    comp.options = sep_options[sep_choice - 1];
                }

                components.push_back(comp);
            }

            std::cout << "✓ Component added! Total components: " << components.size() << "\n";
        }

        if (components.empty()) {
            std::cout << "No components added\n";
            return;
        }

        std::cout << "\nCreating password from " << components.size() << " components...\n";

        // Generate multiple variants
        std::vector<std::string> passwords;
        for (int i = 0; i < 3; i++) {
            std::string password = gen.buildCustomPassword(components);
            passwords.push_back(password);

            auto analysis = gen.checkPasswordStrength(password);
            std::cout << "\n" << (i + 1) << ". " << password << "\n";
            std::cout << "   Heuristic rating: " << analysis.strength << " | Length: " << analysis.length
                      << " | Score: " << analysis.score << "\n";
        }

        if (askYesNo("\nSave one of the passwords?", true)) {
            int choice = askNumber("Choose password to save (1-3)", 1, 3, 1);
            savePasswordToFile(passwords[choice - 1]);
        }
    }

    void createStandardPassword() {
        std::cout << "\n--- STANDARD PASSWORD ---\n";

        int length = askNumber("Password length", 4, 128, 12);

        std::cout << "\nCharacter types:\n";
        bool use_uppercase = askYesNo("Use uppercase letters (A-Z)?", true);
        bool use_lowercase = askYesNo("Use lowercase letters (a-z)?", true);
        bool use_digits = askYesNo("Use digits (0-9)?", true);
        bool use_special = askYesNo("Use special characters (!@#$%^&*)?", true);

        if (!use_uppercase && !use_lowercase && !use_digits && !use_special) {
            std::cout << "At least one character type must be selected. Enabling all types.\n";
            use_uppercase = use_lowercase = use_digits = use_special = true;
        }

        bool exclude_ambiguous = askYesNo("Exclude ambiguous characters (i,l,1,L,o,0,O)?", false);

        std::cout << "\nMinimum requirements (0 = not required):\n";
        int min_uppercase = use_uppercase ? askNumber("Minimum uppercase letters", 0, length / 2, 1) : 0;
        int min_lowercase = use_lowercase ? askNumber("Minimum lowercase letters", 0, length / 2, 1) : 0;
        int min_digits = use_digits ? askNumber("Minimum digits", 0, length / 2, 1) : 0;
        int min_special = use_special ? askNumber("Minimum special characters", 0, length / 2, 1) : 0;

        try {
            std::string password = gen.generatePassword(length, use_uppercase, use_lowercase,
                                                       use_digits, use_special, exclude_ambiguous,
                                                       min_uppercase, min_lowercase, min_digits, min_special);

            std::cout << "\nGenerated password: " << password << "\n";

            auto analysis = gen.checkPasswordStrength(password);
            std::cout << "Heuristic rating: " << analysis.strength << " (score: " << analysis.score << ")\n";

            if (askYesNo("\nSave password to file?", false)) {
                savePasswordToFile(password);
            }

        } catch (const std::exception& e) {
            std::cout << "Error: " << e.what() << "\n";
        }
    }

    void createMemorablePassword() {
        std::cout << "\n--- MEMORABLE PASSWORD ---\n";

        int num_words = askNumber("Number of words", 2, 8, 6);

        std::cout << "\nChoose separator:\n";
        std::cout << "1. Hyphen (-)\n";
        std::cout << "2. Underscore (_)\n";
        std::cout << "3. Dot (.)\n";
        std::cout << "4. No separator\n";

        int separator_choice = askNumber("Choose option", 1, 4, 1);
        std::vector<std::string> separators = {"-", "_", ".", ""};
        std::string separator = separators[separator_choice - 1];

        bool capitalize = askYesNo("Capitalize first letters?", true);
        bool add_numbers = askYesNo("Add numbers at the end?", true);

        int word_min_length = askNumber("Minimum word length", 3, 10, 4);
        int word_max_length = askNumber("Maximum word length", word_min_length, 15, 8);

        std::string password = gen.generateMemorablePassword(num_words, separator, add_numbers,
                                                            capitalize, word_min_length, word_max_length);

        std::cout << "\nGenerated password: " << password << "\n";

        auto analysis = gen.checkPasswordStrength(password);
        std::cout << "Heuristic rating: " << analysis.strength << " (score: " << analysis.score << ")\n";

        if (askYesNo("\nSave password to file?", false)) {
            savePasswordToFile(password);
        }
    }

    void createComplexMemorablePassword() {
        std::cout << "\n--- COMPLEX MEMORABLE PASSWORD ---\n";

        int num_words = askNumber("Number of words", 2, 6, 3);
        bool add_special_chars = askYesNo("Add special characters?", true);
        bool add_numbers = askYesNo("Add numbers?", true);
        bool transform_words = askYesNo("Apply word transformations (letter to number replacements)?", true);
        int min_length = askNumber("Minimum password length", 12, 50, 16);

        std::cout << "\nGenerating options...\n";

        std::vector<std::string> passwords;
        for (int i = 0; i < 3; i++) {
            std::string password = gen.generateComplexMemorablePassword(num_words, add_special_chars,
                                                                       add_numbers, transform_words, min_length);
            passwords.push_back(password);

            auto analysis = gen.checkPasswordStrength(password);
            std::cout << "\n" << (i + 1) << ". " << password << "\n";
            std::cout << "   Heuristic rating: " << analysis.strength << " | Length: " << analysis.length
                      << " | Score: " << analysis.score << "\n";
        }

        int choice = askNumber("\nChoose password to save (1-3, 0 = don't save)", 0, 3, 0);

        if (choice > 0) {
            std::cout << "\nSelected password: " << passwords[choice - 1] << "\n";

            if (askYesNo("Save password to file?", false)) {
                savePasswordToFile(passwords[choice - 1]);
            }
        }
    }

    void createPasswordByComplexity() {
        std::cout << "\n--- PASSWORD BY COMPLEXITY LEVEL ---\n";
        std::cout << "Choose complexity level from 1 to 10:\n\n";

        for (int i = 1; i <= 10; i++) {
            std::cout << std::setw(2) << i << ". " << gen.getComplexityDescription(i) << "\n";
        }

        std::cout << "\n";
        int complexity = askNumber("Choose complexity level", 1, 10, 5);

        std::cout << "\nSelected level: " << gen.getComplexityDescription(complexity) << "\n";

        int count = askNumber("Number of password variants", 1, 10, 3);

        std::cout << "\nGenerated passwords (complexity level " << complexity << "):\n";
        std::vector<std::string> passwords;

        for (int i = 0; i < count; i++) {
            try {
                std::string password = gen.generatePasswordByComplexity(complexity);
                passwords.push_back(password);

                auto analysis = gen.checkPasswordStrength(password);

                std::cout << "\n" << (i + 1) << ". " << password << "\n";
                std::cout << "   Heuristic rating: " << analysis.strength << " | Length: " << analysis.length
                          << " | Score: " << analysis.score << "/15\n";

                std::vector<std::string> composition;
                if (analysis.has_lowercase) composition.push_back("lowercase");
                if (analysis.has_uppercase) composition.push_back("uppercase");
                if (analysis.has_digits) composition.push_back("digits");
                if (analysis.has_special) composition.push_back("special");

                std::cout << "   Composition: ";
                for (size_t j = 0; j < composition.size(); j++) {
                    std::cout << composition[j];
                    if (j < composition.size() - 1) std::cout << ", ";
                }
                std::cout << "\n";

            } catch (const std::exception& e) {
                std::cout << "Error generating password " << (i + 1) << ": " << e.what() << "\n";
            }
        }

        if (!passwords.empty()) {
            if (askYesNo("\nSave passwords to file?", false)) {
                savePasswordsToFile(passwords);
            }

            if (passwords.size() > 1 && askYesNo("Save one selected password separately?", false)) {
                int choice = askNumber("Choose password (1-" + std::to_string(passwords.size()) + ")",
                                     1, passwords.size());
                savePasswordToFile(passwords[choice - 1]);
            }
        }
    }

    void createMultiplePasswords() {
        std::cout << "\n--- MULTIPLE PASSWORDS ---\n";

        int count = askNumber("Number of passwords to generate", 1, 50, 5);

        std::cout << "\nChoose password type:\n";
        std::cout << "1. Standard passwords\n";
        std::cout << "2. Memorable passwords\n";
        std::cout << "3. Complex memorable passwords\n";

        int password_type = askNumber("Choose type", 1, 3, 1);

        std::cout << "\nGenerated passwords:\n";
        std::vector<std::string> passwords;

        int length = 0, num_words = 0;
        if (password_type == 1) {
            length = askNumber("Password length", 4, 128, 12);
        } else if (password_type == 2) {
            num_words = askNumber("Number of words", 2, 8, 6);
        } else {
            num_words = askNumber("Number of words", 2, 6, 3);
        }

        for (int i = 0; i < count; i++) {
            try {
                std::string password;
                if (password_type == 1) {
                    password = gen.generatePassword(length);
                } else if (password_type == 2) {
                    password = gen.generateMemorablePassword(num_words);
                } else {
                    password = gen.generateComplexMemorablePassword(num_words);
                }

                passwords.push_back(password);
                auto analysis = gen.checkPasswordStrength(password);
                std::cout << std::setw(2) << (i + 1) << ". " << password << " | "
                          << analysis.strength << " (" << analysis.score << " points)\n";

            } catch (const std::exception& e) {
                std::cout << "Error generating password " << (i + 1) << ": " << e.what() << "\n";
            }
        }

        if (!passwords.empty() && askYesNo("\nSave all passwords to file?", false)) {
            savePasswordsToFile(passwords);
        }
    }

    void checkPasswordStrength() {
        std::cout << "\n--- PASSWORD STRENGTH CHECK ---\n";

        std::string password = askString("Enter password to check");

        if (password.empty()) {
            std::cout << "Password cannot be empty\n";
            return;
        }

        auto analysis = gen.checkPasswordStrength(password);

        std::cout << "\nPASSWORD ANALYSIS: '" << password << "'\n";
        std::cout << std::string(50, '=') << "\n";
        std::cout << "Heuristic rating (not an entropy estimate): " << analysis.strength << "\n";
        std::cout << "Length: " << analysis.length << " characters\n";
        std::cout << "Score: " << analysis.score << "/15\n";
        std::cout << "Unique characters: " << analysis.unique_chars << "\n";

        std::cout << "\nPassword composition:\n";
        std::cout << "   • Lowercase letters: " << (analysis.has_lowercase ? "✓" : "✗") << "\n";
        std::cout << "   • Uppercase letters: " << (analysis.has_uppercase ? "✓" : "✗") << "\n";
        std::cout << "   • Digits: " << (analysis.has_digits ? "✓" : "✗") << "\n";
        std::cout << "   • Special characters: " << (analysis.has_special ? "✓" : "✗") << "\n";

        if (!analysis.feedback.empty()) {
            std::cout << "\nRecommendations:\n";
            for (const auto& tip : analysis.feedback) {
                std::cout << "   • " << tip << "\n";
            }
        }
    }

    void quickGenerate() {
        std::cout << "\n--- QUICK GENERATION ---\n";

        std::cout << "Choose quick generation type:\n";
        std::cout << "1. Standard password (16 characters)\n";
        std::cout << "2. Short password (8 characters)\n";
        std::cout << "3. Long password (24 characters)\n";
        std::cout << "4. Memorable password\n";
        std::cout << "5. Complex memorable password\n";

        int quick_type = askNumber("Choose type", 1, 5, 1);
        int count = askNumber("Number of passwords", 1, 10, 3);

        std::cout << "\nGenerated passwords:\n";
        std::vector<std::string> passwords;

        for (int i = 0; i < count; i++) {
            std::string password;

            switch (quick_type) {
                case 1:
                    password = gen.generatePassword(16);
                    break;
                case 2:
                    password = gen.generatePassword(8);
                    break;
                case 3:
                    password = gen.generatePassword(24);
                    break;
                case 4:
                    password = gen.generateMemorablePassword();
                    break;
                case 5:
                    password = gen.generateComplexMemorablePassword();
                    break;
            }

            passwords.push_back(password);
            auto analysis = gen.checkPasswordStrength(password);
            std::cout << (i + 1) << ". " << password << " | " << analysis.strength << "\n";
        }

        if (askYesNo("\nSave passwords to file?", false)) {
            savePasswordsToFile(passwords);
        }
    }

    void savePasswordToFile(const std::string& password) {
        try {
            std::time_t now = std::time(nullptr);
            std::tm* local_time = std::localtime(&now);

            std::ostringstream timestamp;
            timestamp << std::put_time(local_time, "%Y-%m-%d %H:%M:%S");

            std::ostringstream contents;
            contents << "Generated password (" << timestamp.str() << "):\n";
            contents << password << "\n";
            writePrivateFile("password.txt", contents.str());

            std::cout << "Password saved to 'password.txt' (owner-only permissions where supported)\n";
        } catch (const std::exception& e) {
            std::cout << "Error saving: " << e.what() << "\n";
        }
    }

    void savePasswordsToFile(const std::vector<std::string>& passwords) {
        try {
            std::time_t now = std::time(nullptr);
            std::tm* local_time = std::localtime(&now);

            std::ostringstream timestamp;
            timestamp << std::put_time(local_time, "%Y-%m-%d %H:%M:%S");

            std::ostringstream contents;
            contents << "Generated passwords (" << timestamp.str() << "):\n";
            contents << std::string(40, '=') << "\n";

            for (size_t i = 0; i < passwords.size(); i++) {
                contents << (i + 1) << ". " << passwords[i] << "\n";
            }
            writePrivateFile("passwords.txt", contents.str());

            std::cout << passwords.size()
                      << " passwords saved to 'passwords.txt' (owner-only permissions where supported)\n";
        } catch (const std::exception& e) {
            std::cout << "Error saving: " << e.what() << "\n";
        }
    }

    void run() {
        std::cout << "Welcome to Password Generator!\n";
        std::cout << "EFF Diceware wordlist loaded (7776 words).\n";

        while (true) {
            showMenu();

            try {
                std::string choice = askString("\nChoose action (0-8)");

                if (choice == "0") {
                    std::cout << "\nGoodbye! Keep your passwords safe!\n";
                    break;
                } else if (choice == "1") {
                    createStandardPassword();
                } else if (choice == "2") {
                    createMemorablePassword();
                } else if (choice == "3") {
                    createComplexMemorablePassword();
                } else if (choice == "4") {
                    buildCustomPasswordInteractive();
                } else if (choice == "5") {
                    createMultiplePasswords();
                } else if (choice == "6") {
                    checkPasswordStrength();
                } else if (choice == "7") {
                    quickGenerate();
                } else if (choice == "8") {
                    createPasswordByComplexity();
                } else {
                    std::cout << "Invalid choice. Try again.\n";
                }

            } catch (const std::exception& e) {
                std::cout << "Error occurred: " << e.what() << "\n";
                std::cout << "Try again or choose another option.\n";
            }

            std::cout << "\nPress Enter to continue...";
            std::cin.ignore();
        }
    }
};

int main() {
    try {
        UserInterface ui;
        ui.run();
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
