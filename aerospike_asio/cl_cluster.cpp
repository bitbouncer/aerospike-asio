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

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <event2/dns.h>
#include <event2/event.h>

#include "citrusleaf/cf_alloc.h"
#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_base_types.h"
#include "citrusleaf/cf_byte_order.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_digest.h"
#include "citrusleaf/cf_errno.h"
#include "citrusleaf/cf_log_internal.h"
#include "citrusleaf/cf_socket.h"
#include "citrusleaf/proto.h"

#include "ev2citrusleaf.h"
#include "ev2citrusleaf-internal.h"
#include "cl_cluster.h"

static cf_atomic32 g_randomizer = 0;

static const ev2citrusleaf_cluster_runtime_options DEFAULT_RUNTIME_OPTIONS =
{
    300,	// socket_pool_max
    false,	// read_master_only
    false,	// throttle_reads
    false,	// throttle_writes
    2,		// throttle_threshold_failure_pct
    15,		// throttle_window_seconds
    10		// throttle_factor
};

struct ns_partition_map
{
    ns_partition_map(const char* ans, size_t nr_of_partitions) 
    { 
        strcpy(ns, ans);
        owns = new bool[nr_of_partitions];
        for (int i = 0; i != nr_of_partitions; ++i)
            owns[i] = false;
    }
    
    ~ns_partition_map() 
    {
        delete[] owns;
    }

    char	ns[32];
    bool*	owns;
};

static std::vector<ev2citrusleaf_cluster*> s_clusters;
static aerospike::spinlock s_cluster_lock;

std::vector<ev2citrusleaf_cluster*> cl_get_clusters()
{
    aerospike::spinlock::scoped_lock xxx(s_cluster_lock);
    return s_clusters;
}

static void cl_cluster_add(ev2citrusleaf_cluster* c)
{
    aerospike::spinlock::scoped_lock xxx(s_cluster_lock);
    s_clusters.push_back(c);
}

static void cl_cluster_remove(ev2citrusleaf_cluster* c)
{
    aerospike::spinlock::scoped_lock xxx(s_cluster_lock);
    for (std::vector<ev2citrusleaf_cluster*>::iterator i = s_clusters.begin(); i != s_clusters.end(); ++i)
    if (*i == c)
    {
        s_clusters.erase(i);
        break;
    }
}

static ev2citrusleaf_cluster* cl_cluster_head()
{
    aerospike::spinlock::scoped_lock xxx(s_cluster_lock);
    return s_clusters.size() ? *s_clusters.begin() : NULL;
}

//#include <boost/bind.hpp>

// Define to use the old info replicas protocol:
//#define OLD_REPLICAS_PROTOCOL

extern void ev2citrusleaf_base_hop(cl_request *req);

//
// Cumulative contiguous problem score above which the node is considered bad.
//
#define CL_NODE_DUN_THRESHOLD 800

//
// Intervals on which tending happens.
//
struct timeval g_cluster_tend_timeout = {1,200000};
struct timeval g_node_tend_timeout = {1,1};


// Forward references
void cluster_print_stats(ev2citrusleaf_cluster* asc);
void cluster_tend( ev2citrusleaf_cluster *asc);
void cluster_new_sockaddr(ev2citrusleaf_cluster *asc, const sockaddr_in* new_sin);

//
// Utility for splitting a null-terminated string into a vector of sub-strings.
// The vector will have pointers to all the (null-terminated) sub-strings.
// This modifies the input string by inserting nulls.
//
static void str_split(char split_c, char *str, std::vector<char*>& v)
{
    char *prev = str;
    while (*str) 
    {
        if (split_c == *str) 
        {
            *str = 0;
            v.push_back(prev);
            prev = str + 1;
        }
        str++;
    }
    if (prev != str) 
        v.push_back(prev); 
}

// move to member
static inline struct event* cluster_node_get_timer_event(cl_cluster_node* cn)
{
    return (struct event*) cn->_event_space;
}

// move to member
static inline struct event* cluster_node_get_info_event(cl_cluster_node* cn)
{
    return (struct event*)(cn->_event_space + event_get_struct_event_size());
}

// move to member
struct event * cluster_get_timer_event(ev2citrusleaf_cluster *asc)
{
    return((struct event *) &asc->_event_space[0]);
}


static void* run_cluster_mgr(void* base) 
{
    // Blocks until there are no more added events, or until something calls
    // event_base_loopbreak() or event_base_loopexit().
    int result = event_base_dispatch((struct event_base*)base);
    if (result != 0) 
    {
        AEROSPIKE_WARN << "cluster manager event_base_dispatch() returned " << result;
    }
    return NULL;
}

void ev2citrusleaf_cluster::cluster_timer_fn(evutil_socket_t fd, short event, void *udata)
{
    ev2citrusleaf_cluster *asc = (ev2citrusleaf_cluster *)udata;
    uint64_t _s = cf_getms();

    cluster_tend(asc);

    if (++asc->tender_intervals % CL_LOG_STATS_INTERVAL == 0) {
        asc->cl_partition_table_dump();
        cluster_print_stats(asc);
    }

    if (0 != event_add(cluster_get_timer_event(asc), &g_cluster_tend_timeout)) 
    {
        AEROSPIKE_ERROR << "cluster can't reschedule timer, fatal error, no one to report to";
    }

    uint64_t delta = cf_getms() - _s;
    if (delta > CL_LOG_DELAY_INFO)
    {
        AEROSPIKE_INFO << "CL_DELAY: cluster timer: " <<  delta;
    }
}


// move to member...
void node_info_req_free(node_info_req* ir)
{
    if (ir->rbuf) 
        free(ir->rbuf);
    // Includes setting type to INFO_REQ_NONE.
    memset((void*)ir, 0, sizeof(node_info_req));
}

// move to member...
void node_info_req_cancel(cl_cluster_node* cn)
{
    if (cn->info_req.type != node_info_req::INFO_REQ_NONE) 
    {
        event_del(cluster_node_get_info_event(cn));
        node_info_req_free(&cn->info_req);
    }

    if (cn->info_fd != -1) {
        cf_close(cn->info_fd);
        cn->info_fd = -1;
        cf_atomic32_decr(&cn->n_fds_open);
    }
}

ev2citrusleaf_cluster::ev2citrusleaf_cluster(event_base *abase) :
follow(true),
//mgr_thread(NULL), not valid???
//internal_mgr(false),
base(abase),
dns_base(NULL),
//request_q_lock(NULL),
last_node(0),
requests_in_progress(0),
pings_in_progress(0),
n_partitions(0),
tender_intervals(0),
n_nodes_created(0),
n_nodes_destroyed(0),
n_ping_successes(0),
n_ping_failures(0),
n_node_info_successes(0),
n_node_info_failures(0),
n_node_info_timeouts(0),
n_req_successes(0),
n_req_failures(0),
n_req_timeouts(0),
n_req_throttles(0),
n_internal_retries(0),
n_internal_retries_off_q(0),
n_batch_node_successes(0),
n_batch_node_failures(0),
n_batch_node_timeouts(0),
_event_space(NULL)
{
    assert(abase);
    // Note - this keeps this base's event loop alive even with no events added.
    dns_base = evdns_base_new(base, 1);
    _event_space = new uint8_t[event_get_struct_event_size()];

    evtimer_assign(cluster_get_timer_event(this), base, ev2citrusleaf_cluster::cluster_timer_fn, this);

    if (0 != event_add(cluster_get_timer_event(this), &g_cluster_tend_timeout))
    {
        AEROSPIKE_WARN << "could not add the cluster timeout";
    }
    ev2citrusleaf_cluster_set_runtime_options(this, &DEFAULT_RUNTIME_OPTIONS);
}

ev2citrusleaf_cluster::~ev2citrusleaf_cluster()
{
    if (cf_atomic_int_get(requests_in_progress)) 
    {
        AEROSPIKE_WARN << "cluster destroy with requests in progress";
        // Proceed and hope for the best (will likely at least leak memory)...
    }

    // Clear cluster manager timer.
    event_del(cluster_get_timer_event(this));

    // Clear all node timers and node info requests.
    for (std::vector<cl_cluster_node*>::const_iterator i = _nodes.begin(); i != _nodes.end(); ++i)
    {
        node_info_req_cancel(*i);
        event_del(cluster_node_get_timer_event(*i));
        // ... so the event_del() in cl_cluster_node_release() will be a no-op.
    }

    // Clear all outstanding (non-node) internal info requests.
    while (cf_atomic_int_get(pings_in_progress)) 
    {
        // Note - if the event base dispatcher is still active, this generates
        // reentrancy warnings, and may otherwise have unknown effects...
        int loop_result = event_base_loop(base, EVLOOP_ONCE);

        if (loop_result != 0) 
        {
            AEROSPIKE_WARN << "cluster destroy event_base_loop() returns " << loop_result;
            // Proceed and hope for the best...
            break;
        }
    }

    // Destroy all the nodes.
    for (std::vector<cl_cluster_node*>::const_iterator i = _nodes.begin(); i != _nodes.end(); ++i)
    {
        cl_cluster_node_release(*i, "C-");
        cl_cluster_node_release(*i, "L-");
    }

    cl_partition_table_destroy_all();

    if (dns_base)
        evdns_base_free(dns_base, 0);
    delete[] _event_space;
}


cl_cluster_node * ev2citrusleaf_cluster::cluster_node_get(const char *ns, const cf_digest *d, bool write)
{
    cl_cluster_node *cn = 0;
    if (n_partitions) 
    {
        // first, try to get one that matches this digest
        cn = cl_partition_table_get(ns, cl_partition_getid(n_partitions, d), write);
    }

    if (!cn) 
        cn = cluster_node_get_random();

    return cn;
}

cl_partition_table* ev2citrusleaf_cluster::cl_partition_table_create(const char* ns)
{
    cl_partition_table* pt = new cl_partition_table(ns, n_partitions);
    _partition_table_v.push_back(pt);
    return pt;
}

cl_partition_table* ev2citrusleaf_cluster::cl_partition_table_get_by_ns(const char* ns)
{
    for (std::vector<cl_partition_table*>::const_iterator i = _partition_table_v.begin(); i != _partition_table_v.end(); ++i)
    {
        if (strcmp(ns, (*i)->ns) == 0)
            return *i;
    }
    return NULL;
}


cl_cluster_node* ev2citrusleaf_cluster::cl_partition_table_get(const char* ns, cl_partition_id pid, bool write)
{
    cl_partition_table* pt = cl_partition_table_get_by_ns(ns);

    if (!pt)
    {
        return NULL;
    }

    cl_cluster_node* node;
    cl_partition* p = &pt->_partitions[pid];

    aerospike::spinlock::scoped_lock xxx(p->_spinlock);

    if (write || cf_atomic32_get(runtime_options.read_master_only) != 0 ||
        !p->prole) {
        node = p->master;
    }
    else if (!p->master) {
        node = p->prole;
    }
    else {
        uint32_t master_throttle = cf_atomic32_get(p->master->throttle_pct);
        uint32_t prole_throttle = cf_atomic32_get(p->prole->throttle_pct);

        if (master_throttle == 0 && prole_throttle != 0) {
            node = p->master;
        }
        else if (prole_throttle == 0 && master_throttle != 0) {
            node = p->prole;
        }
        else {
            // Both throttling or both ok - roll the dice.
            uint32_t r = (uint32_t)cf_atomic32_incr(&g_randomizer);

            node = (r & 1) ? p->master : p->prole;
        }
    }

    if (node)
        cl_cluster_node_reserve(node, "T+");

    return node;
}

std::vector<std::string> ev2citrusleaf_cluster::get_nodes_names() const
{
    std::vector<std::string> result;
    aerospike::spinlock::scoped_lock xxx(_node_v_lock);
    for (std::vector<cl_cluster_node*>::const_iterator i = _nodes.begin(); i != _nodes.end(); ++i)
        result.push_back((*i)->name);
    return result;
}

//
// Get a likely-healthy node for communication
//

cl_cluster_node* ev2citrusleaf_cluster::cluster_node_get_random()
{
    cl_cluster_node *cn = 0;
    uint32_t i = 0;
    uint32_t node_v_sz = 0;

    aerospike::spinlock::scoped_lock xxx(_node_v_lock);
    do
    {
        // get a node from the node list round-robin
        node_v_sz = (uint32_t) _nodes.size();
        if (node_v_sz == 0)
        {
            AEROSPIKE_DEBUG << "no nodes in this cluster";
            return(0);
        }

        uint32_t node_i = (uint32_t)cf_atomic_int_incr(&last_node);
        if (node_i >= node_v_sz)
        {
            node_i = 0;
            cf_atomic_int_set(&last_node, 0);
        }

        cn = _nodes[node_i];
        i++;

        if (cf_atomic32_get(cn->throttle_pct) != 0) {
            cn = 0;
        }

        if (cn) {
            cl_cluster_node_reserve(cn, "T+");
        }
    } while (cn == 0 && i < node_v_sz);

    return(cn);
}

void 
ev2citrusleaf_cluster::cl_partition_table_destroy_all()
{
    for (std::vector<cl_partition_table*>::const_iterator i = _partition_table_v.begin(); i != _partition_table_v.end(); ++i)
    {
        assert((*i)->_nr_of_partitions == n_partitions);
        for (int j = 0; j != n_partitions; ++j)
        {
            cl_partition* p = &(*i)->_partitions[j];

            if (p->master)
            {
                cl_cluster_node_release(p->master, "PM-");
                p->master = NULL;
            }

            if (p->prole)
            {
                cl_cluster_node_release(p->prole, "PP-");
                p->prole = NULL;
            }
        }
        delete *i;
    }
    _partition_table_v.clear();
}

static inline const char*safe_node_name(cl_cluster_node* node)
{
    return node ? (const char*)node->name : "null";
}


void
ev2citrusleaf_cluster::cl_partition_table_dump()
{
    if (!cf_debug_enabled()) 
    {
        return;
    }

    for (std::vector<cl_partition_table*>::const_iterator i = _partition_table_v.begin(); i != _partition_table_v.end(); ++i)
    {
        if ((*i)->was_dumped)
            continue;
        AEROSPIKE_DEBUG << "--- CLUSTER MAP for " << (*i)->ns << "-- - ";
        for (int pid = 0; pid < n_partitions; pid++)
        {
            cl_partition* p = &(*i)->_partitions[pid];
            aerospike::spinlock::scoped_lock xxx(p->_spinlock);
            AEROSPIKE_DEBUG << pid << ": " << safe_node_name(p->master) << " " << safe_node_name(p->prole);
        }
        (*i)->was_dumped = true;
    }
}

cl_cluster_node::cl_cluster_node(ev2citrusleaf_cluster* parent, const char* aname) :
asc(parent),
intervals_absent(0),
n_successes(0),
n_failures(0),
current_interval(0),
throttle_pct(0),
n_fds_open(0),
partition_generation(-1),
info_fd(-1)
{
    for (int i = 0; i != MAX_HISTORY_INTERVALS; ++i)
    {
        successes[i] = 0;
        failures[i] = 0;
    }
    strcpy(name, aname);
    _event_space = new uint8_t[2 * event_get_struct_event_size()];
}

cl_cluster_node::~cl_cluster_node()
{
    while (!_conn_q.empty())
    {
        int fd = _conn_q.front();
        _conn_q.pop();
        cf_close(fd);
        cf_atomic32_decr(&n_fds_open);
    }
    delete[] _event_space;
}

static char* trim(char *str)
{
	// Warning: This method walks on input string.
	char *begin = str;

	// Trim leading space.
	while (isspace(*begin)) {
		begin++;
	}

	if(*begin == 0) {
		return begin;
	}

	// Trim trailing space. Go to end first so whitespace is preserved in the
	// middle of the string.
	char *end = begin + strlen(begin) - 1;

	while (end > begin && isspace(*end)) {
		end--;
	}
	*(end + 1) = 0;
	return begin;
}

int
ev2citrusleaf_cluster_get_runtime_options(ev2citrusleaf_cluster* asc,
		ev2citrusleaf_cluster_runtime_options* opts)
{
	if (! (asc && opts)) 
    {
        AEROSPIKE_ERROR << "null param";
		return EV2CITRUSLEAF_FAIL_CLIENT_ERROR;
	}

	opts->socket_pool_max = cf_atomic32_get(asc->runtime_options.socket_pool_max);
	opts->read_master_only = cf_atomic32_get(asc->runtime_options.read_master_only) != 0;
	opts->throttle_reads = cf_atomic32_get(asc->runtime_options.throttle_reads) != 0;
	opts->throttle_writes = cf_atomic32_get(asc->runtime_options.throttle_writes) != 0;
	opts->throttle_threshold_failure_pct = asc->runtime_options.throttle_threshold_failure_pct;
	opts->throttle_window_seconds = asc->runtime_options.throttle_window_seconds;
	opts->throttle_factor = asc->runtime_options.throttle_factor;
	return EV2CITRUSLEAF_OK;
}

int
ev2citrusleaf_cluster_set_runtime_options(ev2citrusleaf_cluster* asc,
		const ev2citrusleaf_cluster_runtime_options* opts)
{
	if (! (asc && opts)) 
    {
        AEROSPIKE_ERROR << "null param";
		return EV2CITRUSLEAF_FAIL_CLIENT_ERROR;
	}

	// Really basic sanity checks.
	if (opts->throttle_threshold_failure_pct > 100 ||
		opts->throttle_window_seconds == 0 ||
		opts->throttle_window_seconds > MAX_THROTTLE_WINDOW) {
        AEROSPIKE_ERROR << "illegal option";
		return EV2CITRUSLEAF_FAIL_CLIENT_ERROR;
	}

	cf_atomic32_set(&asc->runtime_options.socket_pool_max, opts->socket_pool_max);

	cf_atomic32_set(&asc->runtime_options.read_master_only, opts->read_master_only ? 1 : 0);

	cf_atomic32_set(&asc->runtime_options.throttle_reads, opts->throttle_reads ? 1 : 0);
    cf_atomic32_set(&asc->runtime_options.throttle_writes, opts->throttle_writes ? 1 : 0);

    {
        aerospike::spinlock::scoped_lock xxx(asc->runtime_options._spinlock);
        asc->runtime_options.throttle_threshold_failure_pct = opts->throttle_threshold_failure_pct;
        asc->runtime_options.throttle_window_seconds = opts->throttle_window_seconds;
        asc->runtime_options.throttle_factor = opts->throttle_factor;
    }

    AEROSPIKE_INFO << "set runtime options:";
    AEROSPIKE_INFO << "   socket-pool-max " << opts->socket_pool_max;
    AEROSPIKE_INFO << "   read-master-only " << opts->read_master_only ? "true" : "false";
    AEROSPIKE_INFO << "   throttle-reads " << (opts->throttle_reads ? "true" : "false") << " writes %s" << opts->throttle_writes ? "true" : "false";
    AEROSPIKE_INFO << 
        "   throttle-threshold-failure-pct " << opts->throttle_threshold_failure_pct << 
        ", window - seconds " << opts->throttle_window_seconds << 
        ", factor " << opts->throttle_factor;

	return EV2CITRUSLEAF_OK;
}


ev2citrusleaf_cluster* ev2citrusleaf_cluster::ev2citrusleaf_cluster_create(event_base *base)
{
    if (!g_ev2citrusleaf_initialized)
    {
        int result = ev2citrusleaf_init();
        if (result != 0) 
        {
            AEROSPIKE_ERROR << "can't initialize cluster, result=" << result;
            return NULL;
        }
    }

    ev2citrusleaf_cluster *asc = new ev2citrusleaf_cluster(base);

    if (asc)
        cl_cluster_add(asc);
    return asc;
}

int
ev2citrusleaf_cluster_get_active_node_count(ev2citrusleaf_cluster* asc)
{
	if (! asc) {
		return EV2CITRUSLEAF_FAIL_CLIENT_ERROR;
	}

    aerospike::spinlock::scoped_lock xxx(asc->_node_v_lock);
    uint32_t n_nodes        = (uint32_t)asc->_nodes.size();
	uint32_t n_active_nodes = 0;

    int index = 0;
    for (std::vector<cl_cluster_node*>::const_iterator i = asc->_nodes.begin(); i != asc->_nodes.end(); ++i, ++index)
    {
        if ((*i)->name[0] == 0) {
            AEROSPIKE_WARN << "cluster node [" << index << "] has no name";
			continue;
		}
        if (!(*i)->_sockaddr_in_v.size()) {
            AEROSPIKE_WARN << "cluster node " << (*i)->name << "[" << index << "] has no address";
			continue;
		}

		n_active_nodes++;
	}
    AEROSPIKE_INFO << "cluster has " << n_nodes << " nodes, " << n_active_nodes << " ok";
	return n_active_nodes;
}


int ev2citrusleaf_cluster_requests_in_progress(ev2citrusleaf_cluster *cl) {
	return (int)cf_atomic_int_get(cl->requests_in_progress);
}


void
ev2citrusleaf_cluster_refresh_partition_tables(ev2citrusleaf_cluster *asc)
{
	if (! asc) 
    {
        AEROSPIKE_WARN << "cluster refresh_partition_tables with null cluster";
		return;
	}
    
    aerospike::spinlock::scoped_lock xxx(asc->_node_v_lock);
    int index = 0; 
    for (std::vector<cl_cluster_node*>::const_iterator i = asc->_nodes.begin(); i != asc->_nodes.end(); ++i, ++index)
    {
        AEROSPIKE_INFO << "forcing cluster node " << (*i)->name << " to get partition info";
        cf_atomic_int_set(&(*i)->partition_generation, (cf_atomic_int_t)-1);
    }
}

void ev2citrusleaf_cluster::ev2citrusleaf_cluster_destroy(ev2citrusleaf_cluster *asc)
{
    //AEROSPIKE_INFO  << "cluster destroy: " << asc;
    cl_cluster_remove(asc);
	delete asc;
}

void
ev2citrusleaf_cluster::ev2citrusleaf_cluster_add_host(const char *host_in, short port_in, bool recheck_now)
{
    AEROSPIKE_DEBUG << "adding host " << host_in << " : " << (int)port_in;
    host_address ha(host_in, port_in);
    aerospike::spinlock::scoped_lock xxx(_spinlock);
    for (std::vector<host_address>::const_iterator i = _hosts.begin(); i != _hosts.end(); ++i)
    {
        if (*i == ha)
            return;
    }
    _hosts.push_back(ha);

    
    // Fire the normal tender function to speed up resolution
    if (!recheck_now)
        cluster_tend(this);
}

void
ev2citrusleaf_cluster_follow(ev2citrusleaf_cluster *asc, bool flag)
{
	asc->follow = flag;
}


//
// NODES NODES NODES
//


//==========================================================
// Periodic node timer functionality.
//

// INFO_STR_MAX_LEN must be >= longest of these strings.
const char INFO_STR_CHECK[] = "node\npartition-generation\nservices\n";
#ifdef OLD_REPLICAS_PROTOCOL
const char INFO_STR_GET_REPLICAS[] = "partition-generation\nreplicas-read\nreplicas-write\n";
#else // OLD_REPLICAS_PROTOCOL
const char INFO_STR_GET_REPLICAS[] = "partition-generation\nreplicas-master\nreplicas-prole\n";
#endif // OLD_REPLICAS_PROTOCOL

void node_info_req_start(cl_cluster_node* cn, node_info_req::node_info_req_type req_type);
// The libevent2 event handler for node info socket events:
void node_info_req_event(evutil_socket_t fd, short event, void* udata);


void
node_info_req_done(cl_cluster_node* cn)
{
	// Success - reuse the socket and approve the node.
    cn->report_success();

	node_info_req_free(&cn->info_req);
	cf_atomic_int_incr(&cn->asc->n_node_info_successes);
}

void
node_info_req_fail(cl_cluster_node* cn, bool remote_failure)
{
	// The socket may have unprocessed data or otherwise be untrustworthy.
	cf_close(cn->info_fd);
	cn->info_fd = -1;
	cf_atomic32_decr(&cn->n_fds_open);

	// If the failure was possibly the server node's fault, disapprove.
	if (remote_failure)
        cn->report_failure();

	node_info_req_free(&cn->info_req);
	cf_atomic_int_incr(&cn->asc->n_node_info_failures);
}


void
node_info_req_timeout(cl_cluster_node* cn)
{
	event_del(cluster_node_get_info_event(cn));
	node_info_req_fail(cn, true);
	cf_atomic_int_incr(&cn->asc->n_node_info_timeouts);
}


ns_partition_map* ns_partition_map_get(std::vector<ns_partition_map*>& p_maps_v, const char* ns, int n_partitions)
{
    for (std::vector<ns_partition_map*>::const_iterator i = p_maps_v.begin(); i != p_maps_v.end(); ++i)
    {
        if (strcmp((*i)->ns, ns) == 0) 
            return *i;
    }

    // new one...
    ns_partition_map* pmap = new ns_partition_map(ns, n_partitions);
    if (!pmap)
    {
        AEROSPIKE_ERROR << ns << " partition map allocation failed";
		return NULL;
	}
	p_maps_v.push_back(pmap);
    return pmap;
}

void
ns_partition_map_destroy(std::vector<ns_partition_map*> p_maps_v)
{
    for (std::vector<ns_partition_map*>::const_iterator i = p_maps_v.begin(); i != p_maps_v.end(); ++i)
    {
        delete *i;
    }
}

// TODO - should probably move base 64 stuff to cf_base so C client can use it.
const uint8_t CF_BASE64_DECODE_ARRAY[] = {
	    /*00*/ /*01*/ /*02*/ /*03*/ /*04*/ /*05*/ /*06*/ /*07*/   /*08*/ /*09*/ /*0A*/ /*0B*/ /*0C*/ /*0D*/ /*0E*/ /*0F*/
/*00*/	    0,     0,     0,     0,     0,     0,     0,     0,       0,     0,     0,     0,     0,     0,     0,     0,
/*10*/      0,     0,     0,     0,     0,     0,     0,     0,       0,     0,     0,     0,     0,     0,     0,     0,
/*20*/	    0,     0,     0,     0,     0,     0,     0,     0,       0,     0,     0,    62,     0,     0,     0,    63,
/*30*/	   52,    53,    54,    55,    56,    57,    58,    59,      60,    61,     0,     0,     0,     0,     0,     0,
/*40*/	    0,     0,     1,     2,     3,     4,     5,     6,       7,     8,     9,    10,    11,    12,    13,    14,
/*50*/	   15,    16,    17,    18,    19,    20,    21,    22,      23,    24,    25,     0,     0,     0,     0,     0,
/*60*/	    0,    26,    27,    28,    29,    30,    31,    32,      33,    34,    35,    36,    37,    38,    39,    40,
/*70*/	   41,    42,    43,    44,    45,    46,    47,    48,      49,    50,    51,     0,     0,     0,     0,     0,
/*80*/	    0,     0,     0,     0,     0,     0,     0,     0,       0,     0,     0,     0,     0,     0,     0,     0,
/*90*/	    0,     0,     0,     0,     0,     0,     0,     0,       0,     0,     0,     0,     0,     0,     0,     0,
/*A0*/	    0,     0,     0,     0,     0,     0,     0,     0,       0,     0,     0,     0,     0,     0,     0,     0,
/*B0*/	    0,     0,     0,     0,     0,     0,     0,     0,       0,     0,     0,     0,     0,     0,     0,     0,
/*C0*/	    0,     0,     0,     0,     0,     0,     0,     0,       0,     0,     0,     0,     0,     0,     0,     0,
/*D0*/	    0,     0,     0,     0,     0,     0,     0,     0,       0,     0,     0,     0,     0,     0,     0,     0,
/*E0*/	    0,     0,     0,     0,     0,     0,     0,     0,       0,     0,     0,     0,     0,     0,     0,     0,
/*F0*/	    0,     0,     0,     0,     0,     0,     0,     0,       0,     0,     0,     0,     0,     0,     0,     0
};

#define B64DA CF_BASE64_DECODE_ARRAY

void
cf_base64_decode(const char* in, int len, uint8_t* out)
{
	int i = 0;
	int j = 0;

	while (i < len) {
		out[j + 0] = (B64DA[in[i + 0]] << 2) | (B64DA[in[i + 1]] >> 4);
		out[j + 1] = (B64DA[in[i + 1]] << 4) | (B64DA[in[i + 2]] >> 2);
		out[j + 2] = (B64DA[in[i + 2]] << 6) |  B64DA[in[i + 3]];

		i += 4;
		j += 3;
	}
}

void
ns_partition_map_set(ns_partition_map* p_map, const char* p_encoded_bitmap,
		int encoded_bitmap_len, int n_partitions)
{
	// First decode the base 64.
	// Size allows for padding - is actual size rounded up to multiple of 3.
	uint8_t* bitmap = (uint8_t*)alloca((encoded_bitmap_len / 4) * 3);

	cf_base64_decode(p_encoded_bitmap, encoded_bitmap_len, bitmap);

	// Then expand the bitmap into our bool array.
	for (int i = 0; i < n_partitions; i++) {
		if ((bitmap[i >> 3] & (0x80 >> (i & 7))) != 0) {
			p_map->owns[i] = true;
		}
	}
}

// Parse the old protocol (to be deprecated):
void
parse_replicas_list(char* list, int n_partitions, std::vector<ns_partition_map*>& p_maps_v)
{
	uint64_t _s = cf_getms();

	// Format: <namespace1>:<partition id1>;<namespace2>:<partition id2>; ...
	// Warning: This method walks on partitions string argument.
	char* p = list;

	while (*p) {
		char* list_ns = p;

		// Loop until : and set it to null.
		while (*p && *p != ':') {
			p++;
		}

		if (*p == ':') {
			*p++ = 0;
		}
		else {
            AEROSPIKE_WARN << "ns " << list_ns << " has no pid";
			break;
		}

		char* list_pid = p;

		// Loop until ; and set it to null.
		while (*p && *p != ';') {
			p++;
		}

		if (*p == ';') {
			*p++ = 0;
		}

		char* ns = trim(list_ns);
		size_t len = strlen(ns);

		if (len == 0 || len > 31) {
            AEROSPIKE_WARN << "invalid partition namespace " << ns;
			continue;
		}

		int pid = atoi(list_pid);

		if (pid < 0 || pid >= n_partitions) {
            AEROSPIKE_WARN << "invalid pid " << list_pid;
			continue;
		}

		ns_partition_map* p_map = ns_partition_map_get(p_maps_v, ns, n_partitions);

		if (p_map) 
        {
			p_map->owns[pid] = true;
		}
	}

	uint64_t delta = cf_getms() - _s;

	if (delta > CL_LOG_DELAY_INFO) 
    {
        AEROSPIKE_INFO << "CL_DELAY: partition process: " << delta;
	}
}

// Parse the new protocol:
void
parse_replicas_map(char* list, int n_partitions, std::vector<ns_partition_map*>& p_maps_v)
{
	uint64_t _s = cf_getms();

	// Format: <namespace1>:<base 64 encoded bitmap>;<namespace2>:<base 64 encoded bitmap>; ...
	// Warning: this method walks on partitions string argument.
	char* p = list;

	while (*p) {
		// Store pointer to namespace string.
		char* list_ns = p;

		// Loop until : and set it to null.
		while (*p && *p != ':') {
			p++;
		}

		if (*p == ':') {
			*p++ = 0;
		}
		else {
            AEROSPIKE_WARN << "ns " << list_ns << " has no encoded bitmap";
			break;
		}

		// Store pointer to base 64 encoded bitmap.
		char* p_encoded_bitmap = p;

		// Loop until ; or null-terminator.
		while (*p && *p != ';') {
			p++;
		}

		// Calculate length of encoded bitmap.
		int encoded_bitmap_len = (int)(p - p_encoded_bitmap);

		// If we found ; set it to null and advance read pointer.
		if (*p == ';') {
			*p++ = 0;
		}

		// Sanity check namespace.
		char* ns = trim(list_ns);
		size_t len = strlen(ns);

		if (len == 0 || len > 31) {
            AEROSPIKE_WARN << "invalid partition namespace " << ns;
			continue;
		}

		// Sanity check encoded bitmap.
		// TODO - annoying to calculate these every time...
		int bitmap_size = (n_partitions + 7) / 8;
		int expected_encoded_len = ((bitmap_size + 2) / 3) * 4;

		if (expected_encoded_len != encoded_bitmap_len) {
            AEROSPIKE_WARN << "invalid partition bitmap " << p_encoded_bitmap;
			continue;
		}

		// Get or create map for specified maps vector and namespace.
		ns_partition_map* p_map = ns_partition_map_get(p_maps_v, ns, n_partitions);

		// Fill out the map's partition ownership information.
		if (p_map) 
        {
			ns_partition_map_set(p_map, p_encoded_bitmap, encoded_bitmap_len, n_partitions);
		}
	}

	uint64_t delta = cf_getms() - _s;

	if (delta > CL_LOG_DELAY_INFO) 
    {
        AEROSPIKE_INFO << "CL_DELAY: partition process: " << delta;
	}
}

void
node_info_req_parse_replicas(cl_cluster_node* cn)
{
    std::vector<ns_partition_map*> read_maps_v; 
    std::vector<ns_partition_map*> write_maps_v;

	//cf_vector_define(read_maps_v, sizeof(ns_partition_map*), 0);
	//cf_vector_define(write_maps_v, sizeof(ns_partition_map*), 0);

	// Returned list format is name1\tvalue1\nname2\tvalue2\n...
    std::vector<char*> lines_v;
	str_split('\n', (char*)cn->info_req.rbuf, lines_v);

    for (std::vector<char*>::const_iterator i = lines_v.begin(); i != lines_v.end(); ++i)
    {
        std::vector<char*> pair_v;
        str_split('\t', *i, pair_v);
        
        // Will happen if a requested field is returned empty.
        if (pair_v.size() != 2)
            continue;

        const char* name  = pair_v[0];
        char* value = pair_v[1];

        if (strcmp(name, "partition-generation") == 0) 
        {
            int gen = atoi(value);

            // Update to the new partition generation.
            cf_atomic_int_set(&cn->partition_generation, (cf_atomic_int_t)gen);
            AEROSPIKE_INFO << "node" << cn->name << " got partition generation " << gen;
        }
        // Old protocol (to be deprecated):
        else if (strcmp(name, "replicas-read") == 0) {
            // Parse the read replicas.
            parse_replicas_list(value, cn->asc->n_partitions, read_maps_v);
        }
        else if (strcmp(name, "replicas-write") == 0) {
            // Parse the write replicas.
            parse_replicas_list(value, cn->asc->n_partitions, write_maps_v);
        }
        // New protocol:
        else if (strcmp(name, "replicas-master") == 0) {
            // Parse the new-format master replicas.
            parse_replicas_map(value, cn->asc->n_partitions, write_maps_v);
        }
        else if (strcmp(name, "replicas-prole") == 0) {
            // Parse the new-format prole replicas.
            parse_replicas_map(value, cn->asc->n_partitions, read_maps_v);
        }
        else 
        {
            AEROSPIKE_WARN << "node " << cn->name << " info replicas did not request " << name;
        }
    }

	// Apply write and read replica maps as masters and proles. For the existing
	// protocol, the read replicas will have proles and masters, but the update
	// function will process write replicas (masters) first and ignore the read
	// replicas' redundant masters.
	//
	// For both old and new protocol, p_read_map will not be null in the single
	// node case. We also assume it's impossible for a node to have no masters.

    
    for (std::vector<ns_partition_map*>::const_iterator i = write_maps_v.begin(); i != write_maps_v.end(); ++i)
    {
        ns_partition_map* p_read_map = ns_partition_map_get(read_maps_v, (*i)->ns, cn->asc->n_partitions);
        cl_partition_table_update(cn, (*i)->ns, (*i)->owns, p_read_map->owns);
    }

    ns_partition_map_destroy(write_maps_v);
	ns_partition_map_destroy(read_maps_v);
	node_info_req_done(cn);
}

// Parse a services string of the form: host:port;host:port;...
uint32_t cluster_services_parse(ev2citrusleaf_cluster *asc, char *services)
{
    std::vector<char*> host_str_v;
	str_split(';', services, host_str_v);


    for (std::vector<char*>::const_iterator i = host_str_v.begin(); i != host_str_v.end(); ++i)
    {
        std::vector<char*> host_port_v;
        str_split(':', *i, host_port_v);

        if (host_port_v.size() == 2) 
        {
            char *host_s = host_port_v[0];
            char *port_s = host_port_v[1];
            int port = atoi(port_s);
            struct sockaddr_in sin;
            // We're guaranteed at this point that the services vector is all
            // a.b.c.d, so async resolver is not necessary.
            if (0 == cl_lookup_immediate(host_s, port, &sin)) 
            {
                // This will initiate a "ping" if the sockaddr is new.
                cluster_new_sockaddr(asc, &sin);
                // Add the string to our host list if it isn't already there.
                asc->ev2citrusleaf_cluster_add_host(host_s, port, false);
            }
        }
    }
    return (uint32_t) host_str_v.size();
}

static bool node_is_split_from_cluster(cl_cluster_node* cn, uint32_t n_services)
{
	// Detect "split cluster" case where this node thinks it's a 1-node cluster.
	// Unchecked, such a node can dominate the partition map and cause all other
	// nodes to be dropped.

	// TODO - perhaps handle "split cluster" cases other than N + 1.

	size_t n_nodes = cn->asc->_nodes.size();

	if (n_services == 0 && n_nodes > 2) 
    {
        AEROSPIKE_WARN << "node " << cn->name << " is 1 - node cluster but client sees " << n_nodes << " nodes";
		return true;
	}
	return false;
}

void
node_info_req_parse_check(cl_cluster_node* cn)
{
	bool get_replicas = false;
	uint32_t n_services = 0;

    std::vector<char*> lines_v;
	str_split('\n', (char*)cn->info_req.rbuf, lines_v);

    for (std::vector<char*>::const_iterator i = lines_v.begin(); i != lines_v.end(); ++i)
    {
        std::vector<char*> pair_v;
        str_split('\t', *i, pair_v);

        // Will happen if a requested field is returned empty.
        if (pair_v.size() != 2) 
            continue;

        char* name  = pair_v[0];
        char* value = pair_v[1];

        if (strcmp(name, "node") == 0) 
        {
                if (strcmp(value, cn->name) != 0) 
                {
                    AEROSPIKE_WARN << "node name changed from " << cn->name << " to " << value;
                    node_info_req_fail(cn, true);
                    return;
                }
            }
            else if (strcmp(name, "partition-generation") == 0) 
            {
                int client_gen = (int)cf_atomic_int_get(cn->partition_generation);
                int server_gen = atoi(value);

                // If generations don't match, flag for replicas request.
                if (client_gen != server_gen) {
                    get_replicas = true;
                    AEROSPIKE_INFO << "node " << cn->name << " partition generation " << client_gen << " needs update to " << server_gen;
                }
            }
            else if (strcmp(name, "services") == 0) {
                // This can spawn an independent info request.
                n_services = cluster_services_parse(cn->asc, value);
            }
            else {
                AEROSPIKE_WARN << "node " << cn->name << " info check did not request" << name;
            }
    }
	node_info_req_done(cn);
	if (get_replicas && ! node_is_split_from_cluster(cn, n_services)) 
    {
        node_info_req_start(cn, node_info_req::INFO_REQ_GET_REPLICAS);
	}
}

bool
node_info_req_handle_send(cl_cluster_node* cn)
{
	node_info_req* ir = &cn->info_req;

	while(true) {
		// Loop until everything is sent or we get would-block.

		if (ir->wbuf_pos >= ir->wbuf_size) {
            AEROSPIKE_ERROR << "unexpected write event";
			node_info_req_fail(cn, false);
			return true;
		}

		int rv = send(cn->info_fd,
				(cf_socket_data_t*)&ir->wbuf[ir->wbuf_pos],
				(cf_socket_size_t)(ir->wbuf_size - ir->wbuf_pos),
				MSG_DONTWAIT | MSG_NOSIGNAL);

		if (rv > 0) {
			ir->wbuf_pos += rv;

			// If done sending, switch to receive mode.
			if (ir->wbuf_pos == ir->wbuf_size) {
				event_assign(cluster_node_get_info_event(cn), cn->asc->base,
						cn->info_fd, EV_READ, node_info_req_event, cn);
				break;
			}

			// Loop, send what's left.
		}
        else if (rv == 0 || (cf_errno() != EAGAIN &&  cf_errno() != EWOULDBLOCK)) {
			// send() supposedly never returns 0.
            AEROSPIKE_DEBUG << "send failed: fd " << cn->info_fd  << " rv " << rv << " errno " << cf_errno();
			node_info_req_fail(cn, true);
			return true;
		}
		else {
			// Got would-block.
			break;
		}
	}

	// Will re-add event.
	return false;
}

bool
node_info_req_handle_recv(cl_cluster_node* cn)
{
	node_info_req* ir = &cn->info_req;

	while (true) {
		// Loop until everything is read from socket or we get would-block.

		if (ir->hbuf_pos < sizeof(cl_proto)) {
			// Read proto header.

			int rv = recv(cn->info_fd,
					(cf_socket_data_t*)&ir->hbuf[ir->hbuf_pos],
					(cf_socket_size_t)(sizeof(cl_proto) - ir->hbuf_pos),
					MSG_DONTWAIT | MSG_NOSIGNAL);

			if (rv > 0) {
				ir->hbuf_pos += rv;
				// Loop, read more header or start reading body.
			}
			else if (rv == 0) {
				// Connection has been closed by the server.
                AEROSPIKE_DEBUG << "recv connection closed: fd " << cn->info_fd;
				node_info_req_fail(cn, true);
				return true;
			}
            else if (cf_errno() != EAGAIN &&  cf_errno() != EWOULDBLOCK) {
                AEROSPIKE_DEBUG << "recv failed: rv " << rv << " errno " << cf_errno();
				node_info_req_fail(cn, true);
				return true;
			}
			else {
				// Got would-block.
				break;
			}
		}
		else {
			// Done with header, read corresponding body.

			// Allocate the read buffer if we haven't yet.
			if (! ir->rbuf) {
				cl_proto* proto = (cl_proto*)ir->hbuf;

				cl_proto_swap(proto);

				ir->rbuf_size = proto->sz;
				ir->rbuf = (uint8_t*)malloc(ir->rbuf_size + 1);

				if (! ir->rbuf) {
                    AEROSPIKE_ERROR << "node info request rbuf allocation failed";
					node_info_req_fail(cn, false);
					return true;
				}

				// Null-terminate this buffer for easier text parsing.
				ir->rbuf[ir->rbuf_size] = 0;
			}

			if (ir->rbuf_pos >= ir->rbuf_size) {
                AEROSPIKE_ERROR << "unexpected read event";
				node_info_req_fail(cn, false);
				return true;
			}

			int rv = recv(cn->info_fd,
					(cf_socket_data_t*)&ir->rbuf[ir->rbuf_pos],
					(cf_socket_size_t)(ir->rbuf_size - ir->rbuf_pos),
					MSG_DONTWAIT | MSG_NOSIGNAL);

			if (rv > 0) {
				ir->rbuf_pos += rv;

				if (ir->rbuf_pos == ir->rbuf_size) {
					// Done with proto body - assume no more protos.

					switch (ir->type) {
                    case node_info_req::INFO_REQ_CHECK:
						// May start a INFO_REQ_GET_REPLICAS request!
						node_info_req_parse_check(cn);
						break;
                    case node_info_req::INFO_REQ_GET_REPLICAS:
						node_info_req_parse_replicas(cn);
						break;
					default:
						// Since we can't assert:
                        AEROSPIKE_ERROR << "node info request invalid type " << ir->type;
						node_info_req_fail(cn, false);
						break;
					}

					return true;
				}

				// Loop, read more body.
			}
			else if (rv == 0) {
				// Connection has been closed by the server.
                AEROSPIKE_DEBUG << "recv connection closed: fd " << cn->info_fd;
				node_info_req_fail(cn, true);
				return true;
			}
            else if (cf_errno() != EAGAIN &&  cf_errno() != EWOULDBLOCK) {
                AEROSPIKE_DEBUG << "recv failed: rv " << rv << " errno" << cf_errno();
				node_info_req_fail(cn, true);
				return true;
			}
			else {
				// Got would-block.
				break;
			}
		}
	}

	// Will re-add event.
	return false;
}

// The libevent2 event handler for node info socket events:
void
node_info_req_event(evutil_socket_t fd, short event, void* udata)
{
	cl_cluster_node* cn = (cl_cluster_node*)udata;
	bool transaction_done;

	if (event & EV_WRITE) {
		// Handle write phase.
		transaction_done = node_info_req_handle_send(cn);
	}
	else if (event & EV_READ) {
		// Handle read phase.
		transaction_done = node_info_req_handle_recv(cn);
	}
	else {
		// Should never happen.
        AEROSPIKE_ERROR << "unexpected event flags " << event;
		node_info_req_fail(cn, false);
		return;
	}

	if (! transaction_done) {
		// There's more to do, re-add event.
		if (0 != event_add(cluster_node_get_info_event(cn), 0)) 
        {
            AEROSPIKE_ERROR << "node info request add event failed";
			node_info_req_fail(cn, false);
		}
	}
}

bool
node_info_req_prep_fd(cl_cluster_node* cn)
{
	if (cn->info_fd != -1) {
		// Socket was left open - check it.
		int result = ev2citrusleaf_is_connected(cn->info_fd);

		switch (result) {
		case CONNECTED:
			// It's still good.
			return true;
		case CONNECTED_NOT:
			// Can't use it - the remote end closed it.
		case CONNECTED_ERROR:
			// Some other problem, could have to do with remote end.
			cf_close(cn->info_fd);
			cn->info_fd = -1;
			cf_atomic32_decr(&cn->n_fds_open);
			break;
		case CONNECTED_BADFD:
			// Local problem, don't try closing.
			cn->info_fd = -1;
			break;
		default:
			// Since we can't assert:
            AEROSPIKE_ERROR << "node " << cn->name << " info request connect state unknown";
			cf_close(cn->info_fd);
			cn->info_fd = -1;
			cf_atomic32_decr(&cn->n_fds_open);
			return false;
		}
	}

	// Try to open a new socket. We'll count any failures here as transaction
	// failures even though we never really start the transaction.
    if (!cn->_sockaddr_in_v.size()) {
        AEROSPIKE_WARN << "node " << cn->name << " has no sockaddrs";
        cn->report_failure();
		return false;
	}
    cn->info_fd = cf_socket_create_and_connect_nb(&*cn->_sockaddr_in_v.begin());
	if (cn->info_fd == -1) {
		// TODO - loop over all sockaddrs?
        cn->report_failure();
		return false;
	}

	cf_atomic32_incr(&cn->n_fds_open);

	return true;
}

void
node_info_req_start(cl_cluster_node* cn, node_info_req::node_info_req_type req_type)
{
	if (! node_info_req_prep_fd(cn)) 
    {
        AEROSPIKE_INFO << "node " << cn->name << " couldn't open fd for info request";
		cf_atomic_int_incr(&cn->asc->n_node_info_failures);
		return;
	}

	const char* names;
	size_t names_len;

	switch (req_type) {
    case node_info_req::INFO_REQ_CHECK:
		names = INFO_STR_CHECK;
		names_len = sizeof(INFO_STR_CHECK) - 1;
		break;
    case node_info_req::INFO_REQ_GET_REPLICAS:
		names = INFO_STR_GET_REPLICAS;
		names_len = sizeof(INFO_STR_GET_REPLICAS) - 1;
		break;
	default:
		// Since we can't assert:
        AEROSPIKE_ERROR << "node " << cn->name << "info request invalid type: " << req_type;
		return;
	}

	cn->info_req.wbuf_size = sizeof(cl_proto) + names_len;

	cl_proto* proto = (cl_proto*)cn->info_req.wbuf;

	proto->sz = names_len;
	proto->version = CL_PROTO_VERSION;
	proto->type = CL_PROTO_TYPE_INFO;
	cl_proto_swap(proto);

	strncpy((char*)(cn->info_req.wbuf + sizeof(cl_proto)), names, names_len);

	event_assign(cluster_node_get_info_event(cn), cn->asc->base,
			cn->info_fd, EV_WRITE, node_info_req_event, cn);

	if (0 != event_add(cluster_node_get_info_event(cn), 0)) {
        AEROSPIKE_ERROR << "node " << cn->name << " info request add event failed";
	}
	else {
		cn->info_req.type = req_type;
	}
}

// TODO - add to runtime options?
#define MAX_THROTTLE_PCT 90

void
node_throttle_control(cl_cluster_node* cn)
{
    // Get the throttle control parameters.
    uint32_t threshold_failure_pct = 0;
    uint32_t history_intervals_to_use = 0;
    uint32_t throttle_factor = 0;


    threadsafe_runtime_options* p_opts = &cn->asc->runtime_options;
    {
        aerospike::spinlock::scoped_lock xxx(p_opts->_spinlock);
        threshold_failure_pct    = p_opts->throttle_threshold_failure_pct;
        history_intervals_to_use = p_opts->throttle_window_seconds - 1;
        throttle_factor          = p_opts->throttle_factor;
    }

	// Collect and reset the latest counts. TODO - atomic get and clear?
	uint32_t new_successes = cf_atomic32_get(cn->n_successes);
	uint32_t new_failures = cf_atomic32_get(cn->n_failures);

	cf_atomic32_set(&cn->n_successes, 0);
	cf_atomic32_set(&cn->n_failures, 0);

	// Figure out where to start summing history, and if there's enough history
	// to base throttling on. (If not, calculate sums anyway for debug logging.)
	uint32_t start_interval = 0;
	bool enough_history = false;

	if (cn->current_interval >= history_intervals_to_use) {
		start_interval = cn->current_interval - history_intervals_to_use;
		enough_history = true;
	}

	// Calculate the sums.
	uint64_t successes_sum = new_successes;
	uint64_t failures_sum = new_failures;

	for (uint32_t i = start_interval; i < cn->current_interval; i++) {
		uint32_t index = i % MAX_HISTORY_INTERVALS;

		successes_sum += cn->successes[index];
		failures_sum += cn->failures[index];
	}

	// Update the history. Keep max history in case runtime options change.
	uint32_t current_index = cn->current_interval % MAX_HISTORY_INTERVALS;

	cn->successes[current_index] = new_successes;
	cn->failures[current_index] = new_failures;

	// So far we only use this for throttle control - increment it here.
	cn->current_interval++;

	// Calculate the failure percentage. Work in units of tenths-of-a-percent
	// for finer resolution of the resulting throttle percent.
	uint64_t sum = failures_sum + successes_sum;
	uint32_t failure_tenths_pct =
			sum == 0 ? 0 : (uint32_t)((failures_sum * 1000) / sum);

	// TODO - anything special for a 100% failure rate? Several seconds of all
	// failures with 0 successes might mean we should destroy this node?

	// Calculate and apply the throttle rate.
	uint32_t throttle_pct = 0;
	uint32_t threshold_tenths_pct = threshold_failure_pct * 10;

	if (enough_history && failure_tenths_pct > threshold_tenths_pct) {
		throttle_pct = ((failure_tenths_pct - threshold_tenths_pct) *
				throttle_factor) / 10;

		if (throttle_pct > MAX_THROTTLE_PCT) {
			throttle_pct = MAX_THROTTLE_PCT;
		}
	}

    AEROSPIKE_DEBUG << "node " << cn->name << " recent successes " << successes_sum << ", failures " << failures_sum << ", failure - tenths - pct " << failure_tenths_pct << "  throttle - pct " << throttle_pct;
	cf_atomic32_set(&cn->throttle_pct, throttle_pct);
}

// The libevent2 event handler for node periodic timer events:
void
node_timer_fn(evutil_socket_t fd, short event, void* udata)
{
	cl_cluster_node* cn = (cl_cluster_node*)udata;
	uint64_t _s = cf_getms();

    AEROSPIKE_DEBUG << "node " << cn->name << " timer event";

	// Check if this node is in the partition map. (But skip the first time this
	// node's timer fires, since the node can't be in the map yet.)
	if (cn->intervals_absent == 0 || cl_partition_table_is_node_present(cn)) {
		cn->intervals_absent = 1;
	}
	else if (cn->intervals_absent++ > MAX_INTERVALS_ABSENT) 
    {
		// This node has been out of the map for MAX_INTERVALS_ABSENT laps.
		ev2citrusleaf_cluster* asc = cn->asc;
        AEROSPIKE_INFO << "node " << cn->name << " not in map, removing from cluster " << asc;
		// If there's still a node info request in progress, cancel it.
		node_info_req_cancel(cn);

		// Remove this node object from the cluster list, if there.
        bool deleted = false;
        {
            aerospike::spinlock::scoped_lock xxx(asc->_node_v_lock);
            for (std::vector<cl_cluster_node*>::iterator i = asc->_nodes.begin(); i != asc->_nodes.end(); ++i)
            {
                if (cn == *i)
                {
                    asc->_nodes.erase(i);
                    deleted = true;
                    break;
                }
            }
        }

		// Release cluster's reference, if there was one.
		if (deleted) {
			cl_cluster_node_release(cn, "C-");
		}

		// Release periodic timer reference.
		cl_cluster_node_release(cn, "L-");

		uint64_t delta = cf_getms() - _s;

		if (delta > CL_LOG_DELAY_INFO) {
            AEROSPIKE_INFO << "CL_DELAY: node removed " << delta;
		}

		// Stops the periodic timer.
		return;
	}

	node_throttle_control(cn);

    if (cn->info_req.type != node_info_req::INFO_REQ_NONE) {
		// There's still a node info request in progress. If it's taking too
		// long, cancel it and start over.

		// TODO - more complex logic to decide whether to cancel or let it ride.

		if (++cn->info_req.intervals >= NODE_INFO_REQ_MAX_INTERVALS) {
            AEROSPIKE_DEBUG << "canceling node " << cn->name << " info request after " << cn->info_req.intervals << "sec";
            node_info_req::node_info_req_type type = cn->info_req.type;
			node_info_req_timeout(cn);
			node_info_req_start(cn, type);
		}
		else 
        {
            AEROSPIKE_DEBUG << "node " << cn->name << " info request incomplete after " << cn->info_req.intervals << " sec";
		}
	}

    if (cn->info_req.type == node_info_req::INFO_REQ_NONE) {
        node_info_req_start(cn, node_info_req::INFO_REQ_CHECK);
	}

	if (0 != event_add(cluster_node_get_timer_event(cn), &g_node_tend_timeout)) {
		// Serious - stops periodic timer! TODO - remove node?
        AEROSPIKE_ERROR << "node " << cn->name << " timer event add failed";
	}

	uint64_t delta = cf_getms() - _s;

	if (delta > CL_LOG_DELAY_INFO) {
        AEROSPIKE_INFO << "CL_DELAY: node timer: " << delta;
	}
}

//
// END - Periodic node timer functionality.
//==========================================================


cl_cluster_node*
cl_cluster_node_create(const char* name, ev2citrusleaf_cluster* asc)
{
    AEROSPIKE_INFO << "creating node, name " << name << " cluster" << asc;

	// Allocate object (including space for events) and zero everything.
    cl_cluster_node* cn = new cl_cluster_node(asc, name); // cluster_node_create();

	if (! cn) {
        AEROSPIKE_WARN << "node " << name << " can't allocate node object";
		return NULL;
	}

	cf_atomic_int_incr(&asc->n_nodes_created);

#ifdef DEBUG_NODE_REF_COUNT
	// To balance the ref-count logs, we need this:
	cf_debug("node reserve: %s %s %p : %d", "O+", name, cn, cf_client_rc_count(cn));
#endif

	// Start node's periodic timer.
	cl_cluster_node_reserve(cn, "L+");
	evtimer_assign(cluster_node_get_timer_event(cn), asc->base, node_timer_fn, cn);

	if (0 != event_add(cluster_node_get_timer_event(cn), &g_node_tend_timeout)) {
        AEROSPIKE_WARN << "node " << name << " can't add periodic timer";
		cl_cluster_node_release(cn, "L-");
		cl_cluster_node_release(cn, "O-");
		return NULL;
	}

	// Add node to cluster.
    cl_cluster_node_reserve(cn, "C+");
    {
        aerospike::spinlock::scoped_lock xxx(asc->_node_v_lock);
        asc->_nodes.push_back(cn);
    }
	// At this point we have "L" and "C" references, don't need "O" any more.
	cl_cluster_node_release(cn, "O-");

	return cn;
}

void
cl_cluster_node_release(cl_cluster_node *cn, const char *msg)
{
	// msg key:
	// O:  original alloc
	// L:  node timer loop
	// C:  cluster node list
	// PR: partition table, read
	// PW: partition table, write
	// T:  transaction

#ifdef DEBUG_NODE_REF_COUNT
	cf_debug("node release: %s %s %p : %d", msg, cn->name, cn, cf_client_rc_count(cn));
#endif

	if (0 == cf_client_rc_release(cn)) 
    {
        AEROSPIKE_INFO << "cluster node destroy: node " << cn->name << " p " << cn;
		cf_atomic_int_incr(&cn->asc->n_nodes_destroyed);

		node_info_req_cancel(cn);

		// AKG
		// If we call event_del() before assigning the event - possible in some
		// failures of cl_cluster_node_create() - the libevent library logs the
		// following:
		//
		// [warn] event_del: event has no event_base set.
		//
		// For now I'm not bothering with a flag to avoid this.

		event_del(cluster_node_get_timer_event(cn));

   /* 	int fd;
        while (!cn->_conn_q.empty())
        {
            fd = cn->_conn_q.front();
            cn->_conn_q.pop();
            cf_close(fd);
            cf_atomic32_decr(&cn->n_fds_open);
        }*/
        delete cn;
	}
}

void
cl_cluster_node_reserve(cl_cluster_node *cn, const char *msg)
{
	// msg key:
	// O:  original alloc
	// L:  node timer loop
	// C:  cluster node list
	// PR: partition table, read
	// PW: partition table, write
	// T:  transaction

#ifdef DEBUG_NODE_REF_COUNT
	cf_debug("node reserve: %s %s %p : %d", msg, cn->name, cn, cf_client_rc_count(cn));
#endif

	cf_client_rc_reserve(cn);
}





cl_cluster_node *
cl_cluster_node_get_byname(ev2citrusleaf_cluster *asc, char *name)
{
    aerospike::spinlock::scoped_lock xxx(asc->_node_v_lock);
    for (std::vector<cl_cluster_node*>::const_iterator i = asc->_nodes.begin(); i != asc->_nodes.end(); ++i)
    {
        if (strcmp(name, (*i)->name) == 0) 
            return(*i);
    }
	return(0);
}

// Put the node back, whatever that means (release the reference count?)

void
cl_cluster_node_put(cl_cluster_node *cn)
{
	cl_cluster_node_release(cn, "T-");
}


// Return values:
// -1 try again right away
// -2 don't try again right away
int
cl_cluster_node_fd_get(cl_cluster_node *cn)
{
	int fd;

    if (!cn->_conn_q.empty())
    {
        fd = cn->_conn_q.front();
        cn->_conn_q.pop();

        // Check to see if existing fd is still connected.
		int rv2 = ev2citrusleaf_is_connected(fd);

		switch (rv2) {
			case CONNECTED:
				// It's still good.
				return fd;
			case CONNECTED_NOT:
				// Can't use it - the remote end closed it.
			case CONNECTED_ERROR:
				// Some other problem, could have to do with remote end.
				cf_close(fd);
				cf_atomic32_decr(&cn->n_fds_open);
				return -1;
			case CONNECTED_BADFD:
				// Local problem, don't try closing.
                AEROSPIKE_WARN <<"bad file descriptor in queue: fd "<< fd;
				return -1;
			default:
				// Since we can't assert:
                AEROSPIKE_ERROR << "bad return value from ev2citrusleaf_is_connected";
				cf_close(fd);
				cf_atomic32_decr(&cn->n_fds_open);
				return -2;
		}
	}

	// Queue was empty, open a new socket and (start) connect.

    if (!cn->_sockaddr_in_v.size()) {
        AEROSPIKE_WARN << "node " << cn->name << " has no sockaddrs";
		return -2;
	}

	if (-1 == (fd = cf_socket_create_nb())) {
		// Local problem.
		return -2;
	}

    AEROSPIKE_DEBUG << "new socket: fd " << fd << " node " << cn->name;

    // Try socket addresses until we connect.
    for (std::vector<sockaddr_in>::const_iterator i = cn->_sockaddr_in_v.begin(); i != cn->_sockaddr_in_v.end(); ++i)
    {
        if (0 == cf_socket_start_connect_nb(fd, &*i)) {
            cf_atomic32_incr(&cn->n_fds_open);
            return fd;
        }
        // TODO - else remove this sockaddr from the list?
    }
	cf_close(fd);

	return -2;
}

void
cl_cluster_node_fd_put(cl_cluster_node *cn, int fd)
{
    if (cn->_conn_q.size() > cf_atomic32_get(cn->asc->runtime_options.socket_pool_max))
    {
        cf_close(fd);
        cf_atomic32_decr(&cn->n_fds_open);
    }
    else
    {
        cn->_conn_q.push(fd);
    }
}


bool
cl_cluster_node_throttle_drop(cl_cluster_node* cn)
{
	uint32_t throttle_pct = cf_atomic32_get(cn->throttle_pct);

	if (throttle_pct == 0) {
		return false;
	}

	return ((uint32_t)rand() % 100) < throttle_pct;
}


//
// Debug function. Should be elsewhere.
//

void
sockaddr_in_dump(const char *prefix, const sockaddr_in *sa_in)
{
	char str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, (void*) &(sa_in->sin_addr), str, INET_ADDRSTRLEN);
    AEROSPIKE_INFO << prefix << str << ":" << (int)ntohs(sa_in->sin_port);
}

void
cluster_dump(ev2citrusleaf_cluster *asc)
{
	if (! cf_debug_enabled()) {
		return;
	}

    AEROSPIKE_DEBUG << "=*=*= cluster " << asc <<  "dump =*=*=";
    AEROSPIKE_DEBUG << "registered hosts:";
    int index = 0;
    for (std::vector<host_address>::const_iterator i = asc->_hosts.begin(); i != asc->_hosts.end(); ++i, ++index)
        AEROSPIKE_DEBUG << " host " << index << ":" << i->hostname << ":" << i->port;

    aerospike::spinlock::scoped_lock xxx(asc->_node_v_lock);
    AEROSPIKE_DEBUG << "nodes: " << asc->_nodes.size();
    index = 0;
    for (std::vector<cl_cluster_node*>::const_iterator i = asc->_nodes.begin(); i != asc->_nodes.end(); ++i, ++index)
    {
        for (std::vector<sockaddr_in>::const_iterator j = (*i)->_sockaddr_in_v.begin(); j != (*i)->_sockaddr_in_v.end(); ++j)
        {
            char str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, (void*)&((*j).sin_addr), str, INET_ADDRSTRLEN);
            AEROSPIKE_DEBUG << " " << index << " " << (*i)->name << ":" << ntohs((*j).sin_port) << " connections(" << (*i)->_conn_q.size() << ")";
        }
    }
    AEROSPIKE_DEBUG << "=*=*= cluster" << asc << "end dump =*=*=";
}

struct ping_nodes_data
{
	sockaddr_in	            sa_in;
	ev2citrusleaf_cluster*  asc;
} ;

//
// per-node 'node' request comes back here - we now know the name associated with this sockaddr
// Check to see whether this node is new or taken, and create new
//
// Early on, the request also gets the number of partitions
//
// The PND was alloc'd must be freed

static void
cluster_ping_node_fn(int return_value, char *values, size_t values_len, void *udata)
{
	ping_nodes_data* pnd = (ping_nodes_data*)udata;
	ev2citrusleaf_cluster* asc = pnd->asc;

	cf_atomic_int_decr(&asc->pings_in_progress);

	if (return_value != 0) {
        AEROSPIKE_WARN << "error on return " << return_value;
		if (values) free(values);
		// BFIX - need to free the data here, otherwise LEAK
		free(udata);
		cf_atomic_int_incr(&asc->n_ping_failures);
		return;
	}

	cf_atomic_int_incr(&asc->n_ping_successes);

    std::vector<char*> lines_v;
    str_split('\n', values, lines_v);

    for (std::vector<char*>::const_iterator i = lines_v.begin(); i != lines_v.end(); ++i)
    {
        std::vector<char*> pair_v;
        str_split('\t', *i, pair_v);
        
        if (pair_v.size() == 2)
        {
            char *name = pair_v[0];
            char *value = pair_v[1];

            if (strcmp(name, "node") == 0)
            {
                // make sure this host already exists, create & add if not
                cl_cluster_node *cn = cl_cluster_node_get_byname(asc, value);
                if (!cn)
                {
                    cn = cl_cluster_node_create(value /*nodename*/, asc);
                }
                if (cn)
                {
                    // add this address to node list
                    cn->_sockaddr_in_v.push_back(pnd->sa_in);
                }
            }
            else if (strcmp(name, "partitions") == 0)
            {
                asc->n_partitions = atoi(value);
            }
        }
    }

	if (values) 
        free(values);
	free(pnd);
    pnd = 0;

    size_t sz = 0;
    // if the cluster had waiting requests, try to restart
    {
        aerospike::spinlock::scoped_lock xxx(asc->_node_v_lock);
        sz = asc->_nodes.size();
    }
	if (sz != 0) 
    {
        while (asc->_request_q.size())
        {
            cl_request* req = asc->_request_q.front();
            asc->_request_q.pop_front();
            ev2citrusleaf_base_hop(req);
        }
	}
}

//
// Call this routine whenever you've discovered a new sockaddr.
// Maybe we already know about it, maybe we don't - this routine will
// 'debounce' efficiently and launch an 'add' cycle if it appears new.
//
void
cluster_new_sockaddr(ev2citrusleaf_cluster *asc, const sockaddr_in* new_sin)
{
    // Lookup the sockaddr in the node list. This is inefficient, but works
    // Improve later if problem...
    {
        aerospike::spinlock::scoped_lock xxx(asc->_node_v_lock);
        for (std::vector<cl_cluster_node*>::const_iterator i = asc->_nodes.begin(); i != asc->_nodes.end(); ++i)
        {
            for (std::vector<sockaddr_in>::const_iterator k = (*i)->_sockaddr_in_v.begin(); k != (*i)->_sockaddr_in_v.end(); ++k)
            {
                if (memcmp(&*k, new_sin, sizeof(struct sockaddr_in)) == 0)
                {
                    // it's old - get out
                    return;
                }
            }
        }
    }

    // have new never-pinged hosts. Do the info_host call to get its name
    // The callback will add the node if it's new
    if (cf_info_enabled()) 
    {
        sockaddr_in_dump("new sockaddr found: ", new_sin);
    }

    ping_nodes_data *pnd = (ping_nodes_data*)malloc(sizeof(ping_nodes_data));
    if (!pnd)	
        return;
    pnd->sa_in = *new_sin;
    pnd->asc = asc;

    if (0 != ev2citrusleaf_info_host(
        asc->base, 
        new_sin, 
        asc->n_partitions == 0 ? "node\npartitions" : "node", 
        0,
        [pnd](int return_value, char *values, size_t values_len)
    {
        cluster_ping_node_fn(return_value, values, values_len, pnd);
    })
        ) // if
    {
		free(pnd);
		cf_atomic_int_incr(&asc->n_ping_failures);
	}
	else 
    {
		cf_atomic_int_incr(&asc->pings_in_progress);
	}
}

void
cluster_tend(ev2citrusleaf_cluster *asc)
{
    AEROSPIKE_DEBUG << "cluster tend: cluster " << asc;

    cluster_dump(asc);

    // For all registered names --- kick off a resolver
    // to see if there are new IP addresses
    // this is kind of expensive, so might need to do it only rarely
    // because, realistically, it never changes. Only go searching for nodes
    // if there are no nodes in the cluster - we've fallen off the edge of the earth
    size_t  sz = 0;
    {
        aerospike::spinlock::scoped_lock xxx(asc->_node_v_lock);
        sz = asc->_nodes.size();
    }

    if (0 == sz) 
    {
        AEROSPIKE_DEBUG << "no nodes remaining";

        for (std::vector<host_address>::const_iterator i = asc->_hosts.begin(); i != asc->_hosts.end(); ++i)
        {
            AEROSPIKE_DEBUG << "lookup hosts: " << i->hostname << ":" << i->port;
            
            struct sockaddr_in sin;
            if (0 == cl_lookup_immediate(i->hostname.c_str(), i->port, &sin)) {
                cluster_new_sockaddr(asc, &sin);
            }
            else 
            {
                cl_lookup(asc->dns_base, *i, [asc](int error, const std::vector<sockaddr_in>& v)
                {
                    AEROSPIKE_INFO << "cluster tend host resolve";
                    if (error)
                        return;
                    for (std::vector<sockaddr_in>::const_iterator i = v.begin(); i != v.end(); ++i)
                            cluster_new_sockaddr(asc, &*i);
                });
            }
        }
    }
    AEROSPIKE_DEBUG << "end tend";
}
//

//
// I actually don't think there will be a lot of shutdowns,
// but use this to remove all the clusters that might have been added
//
int citrusleaf_cluster_shutdown()
{
    while (auto asc = cl_cluster_head()) 
        ev2citrusleaf_cluster::ev2citrusleaf_cluster_destroy(asc);
    return 0;
}
