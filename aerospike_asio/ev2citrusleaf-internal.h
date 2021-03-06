/*
 * The Aerospike libevent C interface.
 *
 * A porting of the standard C interface into libevent land.
 *
 * This is the external, public header file
 *
 * All rights reserved
 * Brian Bulkowski, 2009
 * CitrusLeaf
 */

// do this both the new skool and old skool way which gives the highest correctness,
// speed, and compatibility
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <event2/dns.h>
#include <event2/event.h>

#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_base_types.h"
#include "citrusleaf/cf_digest.h"
//#include "citrusleaf/cf_hooks.h"
#include "citrusleaf/proto.h"

#include "ev2citrusleaf.h"

//
// Some log-oriented primitives.
//

// how much of a delay in any processing loop is considered 'info' material?
#define CL_LOG_DELAY_INFO 10

// How often (cluster tend periods) to dump stats.
#define CL_LOG_STATS_INTERVAL 10

#define CL_LOG_TRANSACTION 1   // turn this on if you want verbose per-transaction logging

#define CL_LOG_RESTARTLOOP_WARN 5

extern bool g_ev2citrusleaf_initialized;

struct cl_cluster_node;
struct sockaddr_in;

struct cl_request 
{
    cl_request(ev2citrusleaf_cluster* asc, struct event_base* base, int timeout_ms, const ev2citrusleaf_write_parameters* wparam, ev2citrusleaf_callback cb);
    ~cl_request(); 
	int                         fd;
	event_base*                 base;
	ev2citrusleaf_cluster*      asc;
    cl_cluster_node*            node;
	int						    timeout_ms;
	ev2citrusleaf_write_policy	wpol;
	ev2citrusleaf_callback      user_cb;
	char 			            ns[33];
	cf_digest 		            d;
	bool 			            write;

	uint8_t*                    wr_buf;     // citrusleaf request packet
	size_t		                wr_buf_pos;  // current write location
	size_t		 	            wr_buf_size;   // total inuse size of buffer

	uint8_t			            rd_header_buf[sizeof(cl_proto)]; // is: a cl_proto
	size_t		                rd_header_pos;

	uint8_t*                    rd_buf; // cl_msg[data] starts here
	size_t		                rd_buf_pos;
	size_t		                rd_buf_size;

	uint32_t		            network_set;
	uint32_t		            timeout_set;
	uint32_t		            base_hop_set;

	uint8_t	                    wr_tmp[1024];
	uint8_t                     rd_tmp[1024];
    uint64_t                    start_time;
    uint8_t*			        _event_space;
};

struct cl_info_request
{
    cl_info_request();
    ~cl_info_request();

	event_base*     base;

	ev2citrusleaf_info_callback user_cb;

	uint8_t*        wr_buf;     // citrusleaf request packet
	size_t		    wr_buf_pos;  // current write location
	size_t		 	wr_buf_size;   // total inuse size of buffer

	uint8_t			rd_header_buf[sizeof(cl_proto)]; // is: a cl_proto
	size_t		    rd_header_pos;

	uint8_t*        rd_buf; // cl_msg[data] starts here
	size_t		    rd_buf_pos;
	size_t		    rd_buf_size;

	// todo: make info requests properly timeout?

	uint8_t         wr_tmp[1024];
    uint8_t*	    _event_space;

};

// Global statistics - these are independent of cluster.
struct cl_statistics
{
	// Info requests made by app via public API.
	cf_atomic_int	app_info_requests;
};

extern cl_statistics g_cl_stats;

extern int ev2citrusleaf_info_host(event_base *base, const sockaddr_in *sa_in, const char *names, int timeout_ms, ev2citrusleaf_info_callback cb);

extern void ev2citrusleaf_request_complete(cl_request *req, bool timedout);


// a very useful function to see if connections are still connected

#define CONNECTED 0
#define CONNECTED_NOT 1
#define CONNECTED_ERROR 2
#define CONNECTED_BADFD 3 // bad FD

extern int ev2citrusleaf_is_connected(int fd);

// Used in ev2citrusleaf.c and cl_batch.c:
void cl_set_value_particular(cl_msg_op* op, ev2citrusleaf_bin* value);
uint8_t* cl_write_header(uint8_t* buf, size_t msg_size, int info1, int info2, uint32_t generation, uint32_t expiration, uint32_t timeout, uint32_t n_fields, uint32_t n_ops);


