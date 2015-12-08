/*
 * A good, basic C client for the Aerospike protocol
 * Creates a library which is linkable into a variety of systems
 *
 * This module does async DNS lookups using the libevent async DNS system
 *
 * Brian Bulkowski, 2009
 * All rights reserved
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <event2/dns.h>
#include <event2/event.h>

#include "citrusleaf/cf_byte_order.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_log_internal.h"
#include "citrusleaf/cf_socket.h"

#include "cl_cluster.h"
#include "ev2citrusleaf-internal.h"


// #define DEBUG 1


//
// Tries to do an immediate, local conversion, which works if it's
// a simple dotted-decimal address instead of an actual hostname
//
// fills out the passed-in sockaddr and returns 0 on succes, -1 otherwise


int
cl_lookup_immediate(const char *hostname, short port, struct sockaddr_in *sin)
{

	uint32_t addr;
	if (1 == inet_pton(AF_INET, hostname, &addr)) {
		memset((void*)sin, 0, sizeof(*sin));
//		sin->sin_addr.s_addr = htonl(addr);
		sin->sin_addr.s_addr = addr;
		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		return(0);
	}
	
	return(-1);
}


//
// Do a lookup on the given name and port.
// Async function using the libevent dns system
// 
// Function will be called back with a stack-allocated
// vector. You can run the vector, look at its size,
// copy bits out.
//
// The lookup function returns an array of the kind of addresses you were looking
// for - so, in this case, uint32
//



struct cl_lookup_state 
{
	cl_lookup_async_fn    cb;
	short                 port;
	struct evdns_request* evdns_req;
};

void
cl_lookup_result_fn(int result, char type, int count, int ttl, void *addresses, void *udata)
{
	cl_lookup_state *cls = (cl_lookup_state *) udata;
	
	uint64_t _s = cf_getms();
    
    std::vector<sockaddr_in> v;

	if ((result == 0) && (count > 0) && (type == DNS_IPv4_A)) 
	{
		uint32_t *s_addr_a = (uint32_t *)addresses;
		for (int i=0;i<count;i++) 
        {
			struct sockaddr_in sin;
			memset((void*)&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr = s_addr_a[i];
			sin.sin_port = htons(cls->port);
            v.push_back(sin);
		}
		
		// callback
        cls->cb(0, v);
	}
	else 
    {
		cls->cb(-1, v);
	}
	delete cls;
	uint64_t delta = cf_getms() - _s;
    if (delta > CL_LOG_DELAY_INFO)
    {
        AEROSPIKE_INFO << "CL DELAY: cl_lookup result fn: " << delta;
    }
}

int cl_lookup(evdns_base *dns_base, const host_address& ha, cl_lookup_async_fn cb)
{
	uint64_t _s = cf_getms();
	cl_lookup_state* cls = new cl_lookup_state();
	if (!cls)	return(-1);
	cls->cb   = cb;
	cls->port = ha.port;
	
	// the req obj is what you use to cancel before the job is done
    cls->evdns_req = evdns_base_resolve_ipv4(dns_base, (const char *) ha.hostname.c_str(), 0 /*search flag*/, cl_lookup_result_fn, cls);
	if (0 == cls->evdns_req) 
    {
        AEROSPIKE_WARN << "libevent dns fail: hostname " << ha.hostname.c_str();
		delete cls;
		uint64_t delta = cf_getms() - _s;
        if (delta > CL_LOG_DELAY_INFO)
        {
            AEROSPIKE_INFO << "CL_DELAY: cl_lookup: error:" << delta;
        }
		return(-1);
	}
	
    uint64_t delta = cf_getms() - _s;
    if (delta > CL_LOG_DELAY_INFO)        
    {
        AEROSPIKE_INFO << "CL_DELAY: cl_lookup: error:" << delta;
    }

	return(0);
}	


