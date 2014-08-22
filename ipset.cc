#include <stdexcept>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "address.hh"
#include "ipset.hh"

using namespace std;

Ipset::Ipset(string &set_name, const vector<string> &domains) :
    name(set_name)
{
    update(domains);
}

void Ipset::reload()
{
    FILE *wfd;
    int res;

    /* can't reliably use netlink interface with old ipsets */
    wfd = popen("ipset -R &>/dev/null", "w");
    if (wfd == NULL)
	throw runtime_error("popen() error");

    fprintf(wfd, "-N %s$ iphash\n", name.c_str());
    for (auto&& address : addresses)
	for (auto&& ip : address.get_ips()) {
	    char nameb[INET_ADDRSTRLEN];

	    if (inet_ntop(AF_INET, &ip, nameb, INET_ADDRSTRLEN) != NULL)
		fprintf(wfd, "-A %s$ %s\n", name.c_str(), nameb);
	    else
		throw runtime_error("inet_ntop() badness");
	}
    fprintf(wfd, "COMMIT\n");
    res = pclose(wfd);
    if (WIFEXITED(res) && WEXITSTATUS(res) == 0 &&
	exec_cmd("ipset -W " + name + "\\$ " + name) &&
	exec_cmd("ipset -X " + name + "\\$"))
	update_needed = false;
    else
	throw logic_error("some ipset err");
}

void Ipset::flag_updated()
{
    update_needed = true;
}

void Ipset::reload_if_needed()
{
    if (update_needed)
	reload();
}

void Ipset::update(const vector<string> &domains)
{
    addresses.clear();
    for (auto&& domain : domains)
	addresses.emplace_back(*this, domain);
    addresses.shrink_to_fit();
    reload();
}

const vector<Address> &Ipset::get_addresses() const
{
    return addresses;
}

bool Ipset::exec_cmd(std::string cmd) const
{
    int res = system(cmd.c_str());
    return (WIFEXITED(res) && WEXITSTATUS(res) == 0);
}
