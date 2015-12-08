/*
 * A good, basic C client for the Aerospike protocol
 * Creates a library which is linkable into a variety of systems
 *
 * First attempt is a very simple non-threaded blocking interface
 * currently coded to C99 - in our tree, GCC 4.2 and 4.3 are used
 *
 * Brian Bulkowski, 2009
 * All rights reserved
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <event2/dns.h>
#include <event2/event.h>

#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_errno.h"
#include "citrusleaf/cf_log_internal.h"
#include "citrusleaf/cf_socket.h"
#include "citrusleaf/proto.h"

#include "cl_cluster.h"
#include "ev2citrusleaf.h"
#include "ev2citrusleaf-internal.h"

// debug
extern  void sockaddr_in_dump(const char *prefix, const sockaddr_in *sa_in);

cl_info_request::cl_info_request() :
base(NULL),
user_cb(),
wr_buf(NULL),
wr_buf_pos(0),
wr_buf_size(0),
rd_header_pos(0),
rd_buf(NULL),
rd_buf_pos(0),
rd_buf_size(0),
_event_space(0)
{
    _event_space = new uint8_t[event_get_struct_event_size()];
}

cl_info_request::~cl_info_request()
{
    if (rd_buf)
        free(rd_buf);
    if (wr_buf)
    {
        if (wr_buf != wr_tmp)
            free(wr_buf);
    }

    delete[] _event_space;
    _event_space = NULL;
}

cl_info_request *
info_request_create()
{
    return new cl_info_request();
}

void
info_request_destroy(cl_info_request *cir)
{

    if (cir->rd_buf)	free(cir->rd_buf);
    if (cir->wr_buf) {
        if (cir->wr_buf != cir->wr_tmp)
            free(cir->wr_buf);
    }
    free(cir);
}

struct event *
    info_request_get_network_event(cl_info_request *cir)
{
        return((struct event *) &cir->_event_space[0]);
    }

/*
** when you expect a single result back, info result into just that string
*/

int
citrusleaf_info_parse_single(char *values, char **value)
{
    while (*values && (*values != '\t'))
        values++;
    if (*values == 0)	return(-1);
    values++;
    *value = values;
    while (*values && (*values != '\n'))
        values++;
    if (*values == 0)	return(-1);
    *values = 0;
    return(0);

}

int
info_make_request(cl_info_request *cir, const char *names)
{
    cir->wr_buf_size = sizeof(cl_proto);
    if (names) {
        uint32_t nameslen = (uint32_t)strlen(names);
        cir->wr_buf_size += nameslen;
        if (names[nameslen - 1] != '\n')
            cir->wr_buf_size++;
    }

    // set up the buffer pointer
    if (cir->wr_buf_size > sizeof(cir->wr_tmp)) {
        cir->wr_buf = (uint8_t*)malloc(cir->wr_buf_size);
        if (!cir->wr_buf)	return(-1);
    }
    else {
        cir->wr_buf = cir->wr_tmp;
    }

    // do byte-by-byte so we can convert :-(	
    if (names) {
        const char *src = names;
        char *dst = (char *)(cir->wr_buf + sizeof(cl_proto));
        while (*src) {
            if ((*src == ';') || (*src == ':') || (*src == ','))
                *dst = '\n';
            else
                *dst = *src;
            src++;
            dst++;
        }
        if (src[-1] != '\n')	*dst = '\n';
    }

    cl_proto *proto = (cl_proto *)cir->wr_buf;
    proto->sz = cir->wr_buf_size - sizeof(cl_proto);
    proto->version = CL_PROTO_VERSION;
    proto->type = CL_PROTO_TYPE_INFO;
    cl_proto_swap(proto);
    return(0);
}


void
info_event_fn(evutil_socket_t fd, short event, void *udata)
{
    cl_info_request *cir = (cl_info_request *)udata;
    int rv;

    uint64_t _s = cf_getms();

    if (event & EV_WRITE) {
        if (cir->wr_buf_pos < cir->wr_buf_size) {
            rv = send(fd, (cf_socket_data_t*)&cir->wr_buf[cir->wr_buf_pos], (cf_socket_size_t)(cir->wr_buf_size - cir->wr_buf_pos), MSG_NOSIGNAL | MSG_DONTWAIT);
            if (rv > 0) {
                cir->wr_buf_pos += rv;
                if (cir->wr_buf_pos == cir->wr_buf_size) {
                    // changing from WRITE to READ requires redoing the set then the add 
                    event_assign(info_request_get_network_event(cir), cir->base, fd, EV_READ, info_event_fn, cir);
                }
            }
            else if (rv == 0) {
                AEROSPIKE_DEBUG << "write info failed: illegal send return 0: errno " << cf_errno();
                goto Fail;
            }
            else if ((cf_errno() != EAGAIN) && (cf_errno() != EWOULDBLOCK)) {
                AEROSPIKE_DEBUG << "write info failed: rv " << rv << " errno " << cf_errno();
                goto Fail;
            }
        }
    }

    if (event & EV_READ) {
        if (cir->rd_header_pos < sizeof(cl_proto)) {
            rv = recv(fd, (cf_socket_data_t*)&cir->rd_header_buf[cir->rd_header_pos], (cf_socket_size_t)(sizeof(cl_proto)-cir->rd_header_pos), MSG_NOSIGNAL | MSG_DONTWAIT);
            if (rv > 0) {
                cir->rd_header_pos += rv;
            }
            else if (rv == 0) {
                AEROSPIKE_WARN << "read info failed: remote close: rv " << rv << " errno " << cf_errno();
                goto Fail;
            }
            else if ((cf_errno() != EAGAIN) && (cf_errno() != EWOULDBLOCK)) {
                AEROSPIKE_WARN << "read info failed: unknown error: rv " << rv << " errno " << cf_errno();
                goto Fail;
            }
        }
        if (cir->rd_header_pos == sizeof(cl_proto)) {
            if (cir->rd_buf_size == 0) {
                // calculate msg size
                cl_proto *proto = (cl_proto *)cir->rd_header_buf;
                cl_proto_swap(proto);

                // set up the read buffer
                cir->rd_buf = (uint8_t*)malloc(proto->sz + 1);
                if (!cir->rd_buf) {
                    AEROSPIKE_WARN << "malloc fail";
                    goto Fail;
                }
                cir->rd_buf[proto->sz] = 0;
                cir->rd_buf_pos = 0;
                cir->rd_buf_size = proto->sz;
            }
            if (cir->rd_buf_pos < cir->rd_buf_size) {
                rv = recv(fd, (cf_socket_data_t*)&cir->rd_buf[cir->rd_buf_pos], (cf_socket_size_t)(cir->rd_buf_size - cir->rd_buf_pos), MSG_NOSIGNAL | MSG_DONTWAIT);
                if (rv > 0) {
                    cir->rd_buf_pos += rv;
                    if (cir->rd_buf_pos >= cir->rd_buf_size) {
                        // caller frees rdbuf
                        (cir->user_cb)(0 /*return value*/, (char*)cir->rd_buf, cir->rd_buf_size);
                        cir->rd_buf = 0;
                        event_del(info_request_get_network_event(cir)); // WARNING: this is not necessary. BOK says it is safe: maybe he's right, maybe wrong.

                        cf_close(fd);
                        info_request_destroy(cir);
                        cir = 0;

                        uint64_t delta = cf_getms() - _s;
                        if (delta > CL_LOG_DELAY_INFO)
                        {
                            AEROSPIKE_INFO << "CL_DELAY cl_info event OK fn: " << delta;
                        }

                        return;
                    }
                }
                else if (rv == 0) {
                    AEROSPIKE_WARN << "failed: remote termination fd " << fd << " cir " << cir << " rv " << rv << " errno " << cf_errno();
                    goto Fail;
                }
                else if ((cf_errno() != EAGAIN) && (cf_errno() != EWOULDBLOCK)) 
                {
                    AEROSPIKE_WARN << "failed: connection has unknown error fd " << fd << " cir " << cir << " rv " << rv << " errno " << cf_errno();
                    goto Fail;
                }
            }
        }
    }

    event_add(info_request_get_network_event(cir), 0 /*timeout*/);

    {
        uint64_t delta = cf_getms() - _s;
        if (delta > CL_LOG_DELAY_INFO)
        {
            AEROSPIKE_INFO << "CL_DELAY cl_info event again fn:" << delta;
        }
    }

    return;

Fail:
    (cir->user_cb) (-1, 0, 0);
    event_del(info_request_get_network_event(cir)); // WARNING: this is not necessary. BOK says it is safe: maybe he's right, maybe wrong.
    cf_close(fd);
    info_request_destroy(cir);

    {
        uint64_t delta = cf_getms() - _s;
        if (delta > CL_LOG_DELAY_INFO)
        {
            AEROSPIKE_INFO << "CL_DELAY fail OK took " << delta;
        }
    }
}



//
// Request the info of a particular sockaddr_in,
// used internally for host-crawling as well as supporting the external interface
//

int
ev2citrusleaf_info_host(struct event_base *base, const sockaddr_in *sa_in, const char *names, int timeout_ms, ev2citrusleaf_info_callback cb)
{
    uint64_t _s = cf_getms();

    cl_info_request *cir = info_request_create();
    if (!cir)	return(-1);

    cir->user_cb = cb;
    cir->base = base;

    // Create the socket a little early, just in case
    int fd = cf_socket_create_and_connect_nb(sa_in);

    if (fd == -1) {
        info_request_destroy(cir);

        uint64_t delta = cf_getms() - _s;
        if (delta > CL_LOG_DELAY_INFO)
        {
            AEROSPIKE_INFO << "CL_DELAY: info host no socket connect " << delta;
        }

        return -1;
    }

    // fill the buffer while I'm waiting
    if (0 != info_make_request(cir, names)) 
    {
        AEROSPIKE_WARN << "buffer fill failed";
        info_request_destroy(cir);
        cf_close(fd);

        uint64_t delta = cf_getms() - _s;
        if (delta > CL_LOG_DELAY_INFO)
        {
            AEROSPIKE_INFO << "CL_DELAY: info host bad request" << delta;
        }
        return(-1);
    }

    // setup for event
    event_assign(info_request_get_network_event(cir), cir->base, fd, EV_WRITE | EV_READ, info_event_fn, (void *)cir);
    event_add(info_request_get_network_event(cir), 0/*timeout*/);

    uint64_t delta = cf_getms() - _s;
    if (delta > CL_LOG_DELAY_INFO)
    {
        AEROSPIKE_INFO << "CL_DELAY: info host standard:" << delta;
    }

    return(0);
}

struct info_resolve_state
{
    ev2citrusleaf_info_callback cb;
    char*                       names;
    uint32_t	                timeout_ms;
    struct event_base*          base;
};

//
// External function is helper which goes after a particular hostname.
//
// TODO: timeouts are wrong here. If there are 3 host names, you'll end up with
// 3x timeout_ms
//

int ev2citrusleaf_info(struct event_base *base, struct evdns_base *dns_base, char *host, short port, char *names, int timeout_ms, ev2citrusleaf_info_callback cb)
{
    host_address ha(host, port);

    cf_atomic_int_incr(&g_cl_stats.app_info_requests);

    int rv = -1;
    info_resolve_state *irs = 0;

    struct sockaddr_in sa_in;
    // if we can resolve immediate, jump directly to resolution
    if (0 == cl_lookup_immediate(host, port, &sa_in))
    {
        if (0 == ev2citrusleaf_info_host(base, &sa_in, names, timeout_ms, cb))
        {
            rv = 0;
            goto Done;
        }
    }
    else
    {
        irs = (info_resolve_state*)malloc(sizeof(info_resolve_state));
        if (!irs)	goto Done;
        irs->cb = cb;
        if (names)
        {
            irs->names = strdup(names);
            if (!irs->names) goto Done;
        }
        else
        {
            irs->names = 0;
        }
        irs->base = base;
        irs->timeout_ms = timeout_ms;
        if (0 != cl_lookup(dns_base, ha, [irs](int error, const std::vector<sockaddr_in>& v)
        {
            if (error)
            {
                AEROSPIKE_INFO << "info resolution: async fail " << error;
                irs->cb(-1 /*return value*/, 0, 0);
                goto DoneX;
            }

            // Got resolution - callback!
            // 
            // WARNING! It looks like a bug to have the possibilities fo multiple callbacks
            // fired from this resolve function.
            //
            for (std::vector<sockaddr_in>::const_iterator i = v.begin(); i != v.end(); ++i)
            {
                if (0 != ev2citrusleaf_info_host(irs->base, &*i, irs->names, irs->timeout_ms, irs->cb))
                {
                    AEROSPIKE_INFO << "info resolution: can't start infohost after resolve just failed";
                    irs->cb(-1 /*return value*/, 0, 0);
                    goto DoneX;
                }
            }
        DoneX:
            free(irs->names);
            free(irs);
        }))
            goto Done;
        irs = 0;
    }
Done:
    if (irs)
    {
        if (irs->names)	free(irs->names);
        free(irs);
    }
    return(rv);
}
