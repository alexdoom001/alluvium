#include <climits>
#include <functional>
#include <queue>
#include <stdexcept>
#include <tuple>
#include <unordered_map>
#include <utility>

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

extern "C" {
#include <s6-dns/s6dns.h>
#include <skalibs/selfpipe.h>
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
    addrq = addr_queue(&Address::greater_ttl);
    for (auto &iset : isets)
	for (auto &addr : iset.second.get_addresses())
	    addrq.push(std::cref(addr));
}

void timeout_event(addr_queue &addrq, ipset_map &isets)
{
    if (!addrq.empty()) {
	while (addrq.top().get().is_expired()) {
	    auto &a = const_cast<Address &> (addrq.top().get());
	    addrq.pop();
	    a.renew();
	    addrq.push(std::cref(a));
	}
	for (auto &iset : isets)
	    iset.second.reload_if_needed();
    }
}

bool sigfd_event(int fd, addr_queue &addrq, ipset_map &isets)
{
    int sign;

    sign = selfpipe_read();
    if (sign < 0 || sign == SIGTERM)
	return false;
    switch (sign) {
    case SIGHUP:
	/* maybe redo with some file dump? */
	for (auto const &iset : isets) {
	    syslog(LOG_INFO, "managing set %s:", iset.first.c_str());
	    for (auto const &addr : iset.second.get_addresses()) {
		syslog(LOG_INFO, "  domain %s, timediff: %lli:", addr.get_name().c_str(),
		       (long long int) addr.get_timediff());
		for (auto const &ip : addr.get_ips()) {
		    char nameb[INET_ADDRSTRLEN];

		    if (inet_ntop(AF_INET, &ip, nameb, INET_ADDRSTRLEN) != NULL)
			syslog(LOG_INFO, "    %s\n", nameb);
		    else
			syslog(LOG_INFO, "    (inet_ntop failed)");
		}
	    }
	}
	while (!addrq.empty()) {
	    auto const &a = addrq.top().get();

	    addrq.pop();
	    syslog(LOG_INFO, "addr queue domain %s, timediff: %lli:", a.get_name().c_str(),
		       (long long int) a.get_timediff());
	    for (auto &ip : a.get_ips()) {
		char nameb[INET_ADDRSTRLEN];

		if (inet_ntop(AF_INET, &ip, nameb, INET_ADDRSTRLEN) != NULL)
		    syslog(LOG_INFO, "  %s\n", nameb);
		else
		    syslog(LOG_INFO, "  (inet_ntop failed)");
	    }
	}
	renew_ttl_queue(addrq, isets);
	break;
    case SIGUSR2: /* renew and reload */
	while (!addrq.empty()) {
	    auto &a = const_cast<Address &> (addrq.top().get());

	    addrq.pop();
	    a.renew();
	}
	renew_ttl_queue(addrq, isets);
	/* fallthrough */
    case SIGUSR1: /* reload */
	for (auto& iset : isets)
	    iset.second.reload();
	break;
    case SIGALRM:
	timeout_event(addrq, isets);
    default: /* ignore */ ;
    }
    return true;
}

ssize_t clifd_event(int fd, ipset_map &isets, struct request &req)
{
    static char readb[4096];
    static unsigned int readc;
    ssize_t ret;

    ret = read(fd, readb + readc, sizeof(readb) - readc - 1);
    if (ret > 0) {
	char *tok;
	bool splittok = false;

	readb[readc + ret] = '\0';
	if (readb[readc + ret - 1] != '\n')
	    splittok = true;
	if (strstr(readb, "\n\n") != NULL ||
	    (readc == 0 && ret == 1 && !splittok))
	    ret = 0;
	tok = strtok(readb + readc, "\n");

	if (req.request == req_types::invalid) {
	    char cmd[sizeof(readb)], set[sizeof(readb)];
	    const char *err = NULL;

	    if (tok != NULL &&
		sscanf(tok, "%s %s", cmd, set) == 2) {
		if ((strcmp(cmd, "update") == 0 ||
		     strcmp(cmd, "drop") == 0)) {
		    if (strlen(set) <= Ipset::max_name_length) {
			req.ipset = string(set);
			if (strcmp(cmd, "update") == 0)
			    req.request = req_types::update;
			else
			    req.request = req_types::drop;
			tok = strtok(NULL, "\n");
		    } else
			err = "bad set name\n";
		} else
		    err = "wrong command\n";
	    } else
		err = "some garbage on input\n";
	    if (err != NULL) {
		write(fd, err, strlen(err));
		ret = -1;
	    }
	}
	if (req.request == req_types::update && tok != NULL) {
	    if (!splittok) {
		do {
		    req.addrs.emplace_back(tok);
		    tok = strtok(NULL, "\n");
		} while (tok != NULL);
		readc = 0;
	    } else {
		char *oldtok = tok;

		while ((tok = strtok(NULL, "\n")) != NULL) {
		    req.addrs.emplace_back(oldtok);
		    oldtok = tok;
		}
		readc = strlen(oldtok);
		memmove(readb, oldtok, readc);
	    }
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

	    try {
		if (oldset != isets.end())
		    oldset->second.update(req.addrs);
		else
		    isets.emplace(piecewise_construct, forward_as_tuple(req.ipset),
				  forward_as_tuple(req.ipset, req.addrs));
	    } catch (const exception &e) {
		retstr = string("error: ") + e.what();
	    }
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
	readc = 0;
    }
    return ret;
}

int main(int const argc, char const * const* const argv)
{
    int sigfd = -1, cmdfd = -1, clifd = -1;
    addr_queue addrq(&Address::greater_ttl);
    ipset_map isets;
    struct request req;
    char const *ctl_path = def_ctl_path;

    openlog("alluvium", 0, LOG_DAEMON);
    req.request = req_types::invalid;
    if (argc == 2 && argv[1] != NULL)
	ctl_path = argv[1];
    {
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGHUP);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGPIPE);
	sigaddset(&set, SIGALRM);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);

	sigfd = selfpipe_init();
	if (sigfd < 0) {
	    syslog(LOG_ERR, "Can't create signal fd");
	    return 1;
	}
	if (selfpipe_trapset(&set) != 0) {
	    syslog(LOG_ERR, "Can't listen to signals we need");
	    return 1;
	}
    }
    if (!s6dns_init()) {
	syslog(LOG_ERR, "Can't init DNS subsystem");
	return 1;
    }

    {
	struct sockaddr_un serv_addr;

	cmdfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (cmdfd < 0) {
	    syslog(LOG_ERR, "Can't create socket");
	    return 1;
	}
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
	if (listen(cmdfd, 1) < 0) {
	    syslog(LOG_ERR, "Error listening on %s socket", ctl_path);
	    close(cmdfd);
	    return 1;
	}
    }

    syslog(LOG_NOTICE, "started");

    while (true) {
	struct pollfd pfd[3];
	int ret;

	pfd[0].fd = sigfd;
	pfd[0].events = POLLIN;
	pfd[1].fd = cmdfd;
	pfd[1].events = POLLIN;
	pfd[2].fd = clifd;
	pfd[2].events = POLLIN;

	if (!addrq.empty()) {
	    time_t diff;
	    unsigned int altime;

	    diff = addrq.top().get().get_timediff();
	    if (diff < 0)
		diff = 0;
	    /* round to the next minute (or 64 seconds really) */
	    diff = (((diff >> 5) + 1) << 5);
	    if (diff > UINT_MAX)
		altime = UINT_MAX;
	    else
		altime = diff;
	    /* use alarm because ms-precision poll timeout is too much */
	    alarm(altime);
	}

	ret = poll(pfd, sizeof(pfd)/sizeof(pfd[0]), -1);
	if (ret < 0)
	    throw runtime_error("poll() failed");
	else if (ret > 0) {
	    if (pfd[0].revents & POLLIN) {
		if (!sigfd_event(sigfd, addrq, isets))
		    break;
	    } else if (pfd[1].revents & POLLIN) {
		int newclifd;

		newclifd = accept(cmdfd, NULL, NULL);
		if (newclifd > 0) {
		    if (clifd > 0)
			close(newclifd);
		    else
			clifd = newclifd;
		}
	    } else if (pfd[2].revents & POLLIN) {
		ssize_t r;

		r = clifd_event(clifd, isets, req);
		if (r == 0) {
		    renew_ttl_queue(addrq, isets);
		    clifd = -1;
		} else if (r < 0)
		    clifd = -1;
	    }
	}
    }

    return 0;
}
