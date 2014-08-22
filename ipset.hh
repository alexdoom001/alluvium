#ifndef IPSET_HPP
#define IPSET_HPP

#include <string>
#include <vector>

#include "address.hh"

class Ipset
{
public:
    Ipset(std::string &set_name, const std::vector<std::string> &domains);

    /* kernel supports 32, minus '\0' and minus one for our '$' trick */
    static const unsigned int max_name_length = 30;

    void reload();
    void flag_updated();
    void reload_if_needed();
    void update(const std::vector<std::string> &domains);
    const std::vector<Address> &get_addresses() const;
    Ipset(const Ipset& i) = delete;

private:
    bool exec_cmd(std::string cmd) const;

    const std::string name;
    std::vector<Address> addresses;
    bool update_needed;
};

#endif
