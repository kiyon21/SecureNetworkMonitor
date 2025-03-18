#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <thread>
#include <mutex>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <map>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

class Logger {
private:
    std::mutex log_mutex;
    std::ofstream log_file;
    
public:
    enum LogLevel { INFO, WARNING, ALERT, ERROR };
    
    Logger(const std::string& filename) {
        log_file.open(filename, std::ios::app);
        if (!log_file.is_open()) {
            std::cerr << "Failed to open log file: " << filename << std::endl;
        }
    }
    
    ~Logger() {
        if (log_file.is_open()) {
            log_file.close();
        }
    }
    
    void log(LogLevel level, const std::string& message) {
        std::lock_guard<std::mutex> lock(log_mutex);
        
        auto now = std::chrono::system_clock::now();
        auto now_time = std::chrono::system_clock::to_time_t(now);
        std::string level_str;
        
        switch (level) {
            case INFO: level_str = "INFO"; break;
            case WARNING: level_str = "WARNING"; break;
            case ALERT: level_str = "ALERT"; break;
            case ERROR: level_str = "ERROR"; break;
        }
        
        std::stringstream ss;
        ss << "[" << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S") << "] "
           << "[" << level_str << "] " << message;
        
        std::cout << ss.str() << std::endl;
        
        if (log_file.is_open()) {
            log_file << ss.str() << std::endl;
        }
    }
};

class Rule {
public:
    enum RuleType { IP_BLACKLIST, PORT_SCAN, SYN_FLOOD, PAYLOAD_PATTERN };
    
    RuleType type;
    std::string name;
    std::string description;
    std::map<std::string, std::string> parameters;
    
    Rule(RuleType t, const std::string& n, const std::string& desc) 
        : type(t), name(n), description(desc) {}
    
    void addParameter(const std::string& key, const std::string& value) {
        parameters[key] = value;
    }
};

class Alert {
public:
    std::string rule_name;
    std::string source_ip;
    std::string dest_ip;
    int source_port;
    int dest_port;
    std::string protocol;
    std::string details;
    std::time_t timestamp;
    
    Alert(const std::string& rule, const std::string& src_ip, const std::string& dst_ip,
          int src_port, int dst_port, const std::string& proto, const std::string& det)
        : rule_name(rule), source_ip(src_ip), dest_ip(dst_ip),
          source_port(src_port), dest_port(dst_port), protocol(proto), details(det) {
        timestamp = std::time(nullptr);
    }
    
    std::string toString() const {
        std::stringstream ss;
        ss << "Alert: " << rule_name << " | "
           << "Source: " << source_ip << ":" << source_port << " | "
           << "Destination: " << dest_ip << ":" << dest_port << " | "
           << "Protocol: " << protocol << " | "
           << "Details: " << details;
        return ss.str();
    }
};

class PacketInfo {
public:
    std::string source_ip;
    std::string dest_ip;
    int source_port;
    int dest_port;
    std::string protocol;
    std::vector<uint8_t> payload;
    std::time_t timestamp;
    
    PacketInfo() : source_port(0), dest_port(0), timestamp(std::time(nullptr)) {}
};

class TrafficAnalyzer {
private:
    std::map<std::string, int> connection_count;
    std::map<std::string, std::time_t> last_connection;
    std::mutex analyzer_mutex;
    
public:
    bool isPortScan(const std::string& source_ip, const std::string& dest_ip, int dest_port) {
        std::lock_guard<std::mutex> lock(analyzer_mutex);
        
        std::string key = source_ip + "-" + dest_ip;
        auto now = std::time(nullptr);
        
        // Reset counter if last connection was more than 60 seconds ago
        if (last_connection.find(key) != last_connection.end() && 
            now - last_connection[key] > 60) {
            connection_count[key] = 0;
        }
        
        connection_count[key]++;
        last_connection[key] = now;
        
        // If more than 10 different ports accessed in 60 seconds, consider it a port scan
        return connection_count[key] > 10;
    }
    
    bool isSynFlood(const std::string& dest_ip, int threshold = 100) {
        // TODO: this would track SYN packets and detect flooding
        return false;
    }
};

class IntrusionDetectionSystem {
private:
    pcap_t* handle;
    std::vector<Rule> rules;
    Logger logger;
    TrafficAnalyzer analyzer;
    std::vector<std::string> blacklisted_ips;
    std::vector<std::string> payload_patterns;
    bool running;
    std::thread capture_thread;
    
    static void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
        IntrusionDetectionSystem* ids = reinterpret_cast<IntrusionDetectionSystem*>(user_data);
        ids->processPacket(pkthdr, packet);
    }
    
    void processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
        PacketInfo info;
        info.timestamp = pkthdr->ts.tv_sec;
        
        // Parse Ethernet header
        const struct ether_header* eth_header = reinterpret_cast<const struct ether_header*>(packet);
        if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
            return; // Not an IP packet
        }
        
        // Parse IP header
        const struct ip* ip_header = reinterpret_cast<const struct ip*>(packet + sizeof(struct ether_header));
        int ip_header_length = ip_header->ip_hl * 4;
        
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        
        info.source_ip = src_ip;
        info.dest_ip = dst_ip;
        
        // Check protocol
        switch (ip_header->ip_p) {
            case IPPROTO_TCP: {
                info.protocol = "TCP";
                const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(
                    packet + sizeof(struct ether_header) + ip_header_length);
                
                info.source_port = ntohs(tcp_header->th_sport);
                info.dest_port = ntohs(tcp_header->th_dport);
                
                // Extract payload
                int tcp_header_length = tcp_header->th_off * 4;
                const u_char* payload_start = packet + sizeof(struct ether_header) + 
                                             ip_header_length + tcp_header_length;
                int payload_length = ntohs(ip_header->ip_len) - (ip_header_length + tcp_header_length);
                
                if (payload_length > 0) {
                    info.payload.assign(payload_start, payload_start + payload_length);
                }
                break;
            }
            case IPPROTO_UDP: {
                info.protocol = "UDP";
                const struct udphdr* udp_header = reinterpret_cast<const struct udphdr*>(
                    packet + sizeof(struct ether_header) + ip_header_length);
                
                info.source_port = ntohs(udp_header->uh_sport);
                info.dest_port = ntohs(udp_header->uh_dport);
                
                // Extract payload
                const u_char* payload_start = packet + sizeof(struct ether_header) + 
                                             ip_header_length + sizeof(struct udphdr);
                int payload_length = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
                
                if (payload_length > 0) {
                    info.payload.assign(payload_start, payload_start + payload_length);
                }
                break;
            }
            default:
                info.protocol = "Other";
                info.source_port = 0;
                info.dest_port = 0;
                break;
        }
        
        // Apply detection rules
        applyRules(info);
    }
    
    void applyRules(const PacketInfo& info) {
        // Check IP blacklist
        if (std::find(blacklisted_ips.begin(), blacklisted_ips.end(), info.source_ip) != blacklisted_ips.end()) {
            Alert alert("IP_BLACKLIST", info.source_ip, info.dest_ip, 
                       info.source_port, info.dest_port, info.protocol,
                       "Traffic from blacklisted IP detected");
            triggerAlert(alert);
        }
        
        // Check for port scanning
        if (analyzer.isPortScan(info.source_ip, info.dest_ip, info.dest_port)) {
            Alert alert("PORT_SCAN", info.source_ip, info.dest_ip, 
                       info.source_port, info.dest_port, info.protocol,
                       "Possible port scanning detected");
            triggerAlert(alert);
        }
        
        // Check for SYN flood (in TCP packets)
        if (info.protocol == "TCP" && analyzer.isSynFlood(info.dest_ip)) {
            Alert alert("SYN_FLOOD", info.source_ip, info.dest_ip, 
                       info.source_port, info.dest_port, info.protocol,
                       "Possible SYN flood attack detected");
            triggerAlert(alert);
        }
        
        // Check payload patterns
        if (!info.payload.empty()) {
            std::string payload_str(info.payload.begin(), info.payload.end());
            for (const auto& pattern : payload_patterns) {
                if (payload_str.find(pattern) != std::string::npos) {
                    Alert alert("PAYLOAD_PATTERN", info.source_ip, info.dest_ip, 
                               info.source_port, info.dest_port, info.protocol,
                               "Suspicious payload pattern detected: " + pattern);
                    triggerAlert(alert);
                    break;
                }
            }
        }
    }
    
    void triggerAlert(const Alert& alert) {
        logger.log(Logger::ALERT, alert.toString());
        // TODO: notify an admin
    }
    
    void captureLoop() {
        pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(this));
    }
    
public:
    IntrusionDetectionSystem() : logger("ids_log.txt"), running(false), handle(nullptr) {
        // Rules
        addRule(Rule(Rule::IP_BLACKLIST, "Blacklisted IP", "Traffic from known malicious IP"));
        addRule(Rule(Rule::PORT_SCAN, "Port Scan", "Multiple ports accessed in short time"));
        addRule(Rule(Rule::SYN_FLOOD, "SYN Flood", "High rate of SYN packets to same destination"));
        addRule(Rule(Rule::PAYLOAD_PATTERN, "Malicious Payload", "Known attack pattern in payload"));
        
        // Add some example blacklisted IPs
        blacklisted_ips.push_back("192.168.1.100");  // Example IP
        
        // Add some example payload patterns to detect
        payload_patterns.push_back("exec(");
        payload_patterns.push_back("SELECT * FROM users");
        payload_patterns.push_back("<script>");
    }
    
    ~IntrusionDetectionSystem() {
        stop();
    }
    
    void addRule(const Rule& rule) {
        rules.push_back(rule);
        logger.log(Logger::INFO, "Added rule: " + rule.name);
    }
    
    bool start(const std::string& interface) {
        char errbuf[PCAP_ERRBUF_SIZE];
        
        // Open the network interface for packet capture
        handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            logger.log(Logger::ERROR, "Failed to open interface: " + std::string(errbuf));
            return false;
        }
        
        // Set a filter to capture only IP packets
        struct bpf_program fp;
        std::string filter = "ip";
        if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            logger.log(Logger::ERROR, "Failed to compile filter: " + std::string(pcap_geterr(handle)));
            pcap_close(handle);
            return false;
        }
        
        if (pcap_setfilter(handle, &fp) == -1) {
            logger.log(Logger::ERROR, "Failed to set filter: " + std::string(pcap_geterr(handle)));
            pcap_freecode(&fp);
            pcap_close(handle);
            return false;
        }
        
        pcap_freecode(&fp);
        
        running = true;
        logger.log(Logger::INFO, "Starting packet capture on interface: " + interface);
        
        // Start packet capture in a separate thread
        capture_thread = std::thread(&IntrusionDetectionSystem::captureLoop, this);
        
        return true;
    }
    
    void stop() {
        if (running) {
            running = false;
            pcap_breakloop(handle);
            
            if (capture_thread.joinable()) {
                capture_thread.join();
            }
            
            pcap_close(handle);
            logger.log(Logger::INFO, "Stopped packet capture");
        }
    }
    
    void addBlacklistedIP(const std::string& ip) {
        blacklisted_ips.push_back(ip);
        logger.log(Logger::INFO, "Added IP to blacklist: " + ip);
    }
    
    void addPayloadPattern(const std::string& pattern) {
        payload_patterns.push_back(pattern);
        logger.log(Logger::INFO, "Added payload pattern: " + pattern);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <interface>" << std::endl;
        return 1;
    }
    
    std::string interface = argv[1];
    IntrusionDetectionSystem ids;
    
    std::cout << "Starting Intrusion Detection System on interface " << interface << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;
    
    if (!ids.start(interface)) {
        std::cerr << "Failed to start IDS" << std::endl;
        return 1;
    }
    
    // Wait for Ctrl+C
    try {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    ids.stop();
    return 0;
}

