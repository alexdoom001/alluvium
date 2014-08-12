#include <functional>
#include <stdexcept>

extern "C" {
#include <skalibs/tai.h>
#include <skalibs/stralloc.h>
}

#include <time.h>

#include "address.hh"
#include "ipset.hh"

using namespace std;

bool Address::greater_ttl(const Address &lhs, const Address &rhs)
{
    return lhs.ttl_exp > rhs.ttl_exp;
}

Address::Address(Ipset &ips, std::string &n) :
    ipset(ips),
    name(n)
{
/*
 * We might cheat here is future, because renew() is time-consuming process
    struct timespec tsp;

    if (!clock_gettime(CLOCK_MONOTONIC_COARSE, &tsp))
	throw runtime_error("bad time");
    ttl_exp = tsp.tv_sec - 1;
 */
    renew();
}

/*
 * Theoretically, it's possible to create many contexts for many addresses and then use
 * s6dns_resolven_loop_g(), but we won't bother for now
 */
void Address::renew()
{
    tain_t deadline;
    s6dns_domain_t s6dom;
    bool cleared_ips = false;

    function<int (s6dns_message_rr_t const *rr, char const *packet,
		  unsigned int packetlen, unsigned int pos,
		  unsigned int section)> handle_dns =
	[&] (s6dns_message_rr_t const *rr, char const *packet,
	     unsigned int packetlen, unsigned int pos,
	     unsigned int section) -> int
	{
	    stralloc s6ips;
	    struct timespec tsp;
	    struct in_addr *inaddr, *eofaddr;

	    memset(&s6ips, 0, sizeof(s6ips));
	    if (!s6dns_message_parse_answer_a(rr, packet, packetlen, pos,
					      section, &s6ips))
		return 0;
	    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &tsp) != 0)
		return 0;
	    ttl_exp = tsp.tv_sec + rr->ttl;

	    if (!cleared_ips) {
		ips.clear();
		cleared_ips = true;
	    }

	    for (inaddr = reinterpret_cast<struct in_addr *> (s6ips.s), 
		     eofaddr = inaddr + (s6ips.len / sizeof(*eofaddr));
		 inaddr < eofaddr; inaddr++)
		ips.push_back(*inaddr);
	    stralloc_free(&s6ips);
	    return 1;
	};

    if (!tain_sysclock(&deadline) || !tain_addsec(&deadline, &deadline, 2))
	throw runtime_error("problem with TAI time management");
    if (!s6dns_domain_fromstring_noqualify_encode(&s6dom, name.c_str(), name.length()))
	throw logic_error("Unable to create s6dns_domain_t");
    if (s6dns_resolve_parse_g(&s6dom, S6DNS_T_A, s6dns_callback, &handle_dns,
			      &deadline) < 0)
	throw logic_error("Error resolving name");
    ipset.flag_updated();
}

const std::vector<struct in_addr> Address::get_ips() const
{
    return ips;
}

bool Address::is_expired() const
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC_COARSE, &ts) != 0)
	return true;
    if (ts.tv_sec >= ttl_exp)
	return true;
    return false;
}

time_t Address::get_ttl() const
{
    return ttl_exp;
}

int Address::s6dns_callback(s6dns_message_rr_t const *rr, char const *packet,
			    unsigned int packetlen, unsigned int pos,
			    unsigned int section, void *stuff)
{
    auto callback = reinterpret_cast<function<int (s6dns_message_rr_t const *rr,
						   char const *packet,
						   unsigned int packetlen,
						   unsigned int pos,
						   unsigned int section)> *> (stuff);
    return (*callback)(rr, packet, packetlen, pos, section);
}
