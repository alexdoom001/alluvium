#ifndef IPSET_HPP
#define IPSET_HPP

#include <string>
#include <vector>

#include "address.hh"

class Ipset
{
public:
    Ipset(std::string &set_name, std::vector<std::string> &domains);

    void reload();
    void flag_updated();
    void reload_if_needed();
    void update(std::vector<std::string> &domains);
    const std::vector<Address> &get_addresses() const;

private:
    const std::string name;
    std::vector<Address> addresses;
    bool update_needed;
};

#endif
