#ifndef ADDRESS_HPP
#define ADDRESS_HPP

#include <string>
#include <vector>

#include <arpa/inet.h>
#include <stdint.h>
#include <time.h>
extern "C" {
#include <s6-dns/s6dns.h>
}

class Ipset;

class Address
{
public:
    static bool greater_ttl(const Address &lhs, const Address &rhs);

    Address(Ipset &ips, const std::string &n);
    Address(const Address& a) = delete;
    Address(Address &&obj);
    void renew();
    const std::vector<struct in_addr> get_ips() const;
    bool is_expired() const;
    time_t get_timediff() const;

private:
    static s6dns_message_rr_func_t s6dns_callback;
    static time_t get_clock_secs();

    Ipset &ipset; /* 1:1 mapping, we tradeoff possible address duplicates for simplicity */
    std::string name;
    time_t ttl_exp;
    std::vector<struct in_addr> ips;
};

#endif
