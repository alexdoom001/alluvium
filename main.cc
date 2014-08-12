#include <functional>
#include <queue>
#include <stdexcept>
#include <tuple>
#include <unordered_map>
#include <utility>

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/poll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

extern "C" {
#include <s6-dns/s6dns.h>
}

#include "ipset.hh"
#include "address.hh"

using namespace std;

static char const def_ctl_path[] = "/var/run/alluvium_ctl";

typedef priority_queue<reference_wrapper<Address const>, vector<reference_wrapper<Address const>>,
		       decltype(&Address::greater_ttl)> addr_queue;
typedef unordered_map<string, Ipset> ipset_map;

enum class req_types {invalid, drop, update};

struct request {
    req_types request;
    string ipset;
    vector<string> addrs;
};

void renew_ttl_queue(addr_queue &addrq, ipset_map &isets)
{
    addrq = {};
    for (auto&& iset : isets)
	for (auto&& addr : iset.second.get_addresses())
	    addrq.push(addr);
}

void timeout_event(addr_queue &addrq, ipset_map &isets)
{
    while (addrq.top().get().is_expired()) {
	auto a = const_cast<Address &> (addrq.top().get());
	addrq.pop();
	a.renew();
	addrq.push(a);
    }
    for (auto& iset : isets)
	iset.second.reload_if_needed();
}

void signal_event()
{
    
}

bool clifd_event(int fd, ipset_map &isets, struct request &req)
{
    static char readb[4096];
    static unsigned int readc;
    ssize_t ret;

    ret = read(fd, readb + readc, sizeof(readb) - readc - 1);
    if (ret > 0) {
	char *tok;

	readb[ret] = '\0';
	if (strstr(readb, "\n\n") != NULL)
	    ret = 0;
	tok = strtok(readb + readc, "\n");

	if (req.request == req_types::invalid) {
	    char cmd[4096], set[4096];

	    if (tok != NULL &&
		sscanf(tok, "%s %s", cmd, set) == 2 &&
		(strcmp(cmd, "update") == 0 ||
		 strcmp(cmd, "drop") == 0)) {
		req.ipset = string(set);
		if (strcmp(cmd, "update") == 0)
		    req.request = req_types::update;
		else
		    req.request = req_types::drop;
		tok = strtok(NULL, "\n");
	    } else
		ret = -1;
	}
	if (req.request == req_types::update && tok != NULL) {
	    char *oldtok = tok;

	    while (tok != NULL) {
		req.addrs.emplace_back(string(tok));
		oldtok = tok;
		tok = strtok(NULL, "\n");
	    }
	    if (ret != 0) {
		readc = strlen(oldtok);
		memmove(readb, oldtok, readc);
	    } else
		readc = 0;
	}
    }

    if (ret == 0) {
	string retstr = "ok\n";

	switch (req.request) {
	case req_types::drop:
	    if (isets.erase(req.ipset) == 0)
		retstr = "set " + req.ipset + " is not found\n";
	    break;
	case req_types::update:
	{
	    auto oldset = isets.find(req.ipset);

	    if (oldset != isets.end())
		oldset->second.update(req.addrs);
	    else
		isets.emplace(piecewise_construct, forward_as_tuple(req.ipset),
			      forward_as_tuple(req.ipset, req.addrs));
	}
	    break;
	case req_types::invalid: ;
	}
	write(fd, retstr.c_str(), retstr.length()); // if it fails, it fails
    }

    if (ret <= 0) {
	req.request = req_types::invalid;
	req.ipset.clear();
	req.addrs.clear();
	close(fd);
	return false;
    }
    return true;
}

int main(int const argc, char const * const* const argv)
{
    int sigfd = -1, cmdfd = -1, clifd = -1;
    addr_queue addrq(&Address::greater_ttl);
    ipset_map isets;
    struct request req;
    char const *ctl_path = def_ctl_path;

    req.request = req_types::invalid;
//    sigfd = signalfd(-1, );
    if (argc == 2 && argv[1] != NULL)
	ctl_path = argv[1];
    cmdfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cmdfd < 0) {
	syslog(LOG_ERR, "Can't create socket");
	return 1;
    }

    if (!s6dns_init())
	return 1;

    {
	struct sockaddr_un serv_addr;

	remove(ctl_path); // ok to fail
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sun_family = AF_UNIX;
	strcpy(serv_addr.sun_path, ctl_path);
	if (bind(cmdfd, reinterpret_cast<struct sockaddr *> (&serv_addr),
		 strlen(serv_addr.sun_path) + sizeof(serv_addr.sun_family)) < 0) {
	    close(cmdfd);
	    syslog(LOG_ERR, "Can't bind to %s socket", ctl_path);
	    return 1;
	}
    }

    if (listen(cmdfd, 1) < 0) {
	syslog(LOG_ERR, "Error listening on %s socket", ctl_path);
	close(cmdfd);
	return 1;
    }

    while (true) {
	struct pollfd pfd[3];
	struct timespec ts;
	int timeout = -1, ret;

	pfd[0].fd = sigfd;
	pfd[0].events = POLLIN;
	pfd[1].fd = cmdfd;
	pfd[1].events = POLLIN;
	pfd[2].fd = clifd;
	pfd[2].events = POLLIN;

	if (!addrq.empty()) {
	    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ts) != 0)
		throw runtime_error("clock_gettime() failed");

	    timeout = (addrq.top().get().get_ttl() - ts.tv_sec + 1) * 1000 * 1000;
	    if (timeout < 0)
		timeout = 0;
	}
	ret = poll(pfd, sizeof(pfd)/sizeof(pfd[0]), timeout);
	if (ret == 0)
	    timeout_event(addrq, isets);
	else if (ret < 0)
	    throw logic_error("poll() failed");
	else if (ret > 0) {
	    if (pfd[0].revents & POLLIN)
		break;
	    else if (pfd[1].revents & POLLIN) {
		int newclifd;

		newclifd = accept(cmdfd, NULL, NULL);
		if (newclifd > 0) {
		    if (clifd > 0)
			close(newclifd);
		    else
			clifd = newclifd;
		}
	    } else if (pfd[2].revents & POLLIN) {
		if (!clifd_event(clifd, isets, req))
		    clifd = -1;
	    }
	}
    }

    return 0;
}