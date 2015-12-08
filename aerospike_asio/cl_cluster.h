/*
 * The Aerospike C interface. A good, basic library that many clients can be based on.
 *
 * This is the internal, non-public header file.
 *
 * this code currently assumes that the server is running in an ASCII-7 based
 * (ie, utf8 or ISO-LATIN-1)
 * character set, as values coming back from the server are UTF-8. We currently
 * don't bother to convert to the character set of the machine we're running on
 * but we advertise these values as 'strings'
 *
 * All rights reserved
 * Brian Bulkowski, 2009
 * CitrusLeaf
 */


// do this both the new skool and old skool way which gives the highest correctness,
// speed, and compatibility
#pragma once

#include <stdint.h>
#include <event2/event.h>
#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_base_types.h"
#include "citrusleaf/cf_digest.h"
#include "citrusleaf/proto.h"
#include "ev2citrusleaf.h"

#include <memory>
#include <queue>
#include <deque>
#include <vector>
#include <string>
#include "spinlock.h"

#define MAX_INTERVALS_ABSENT 1
#define MAX_HISTORY_INTERVALS 64 // power of 2 makes mod operation fast
#define MAX_THROTTLE_WINDOW (MAX_HISTORY_INTERVALS + 1)

#define NODE_INFO_REQ_MAX_INTERVALS 5

// Must be >= longest "names" string sent in a node info request.
#define INFO_STR_MAX_LEN 64

struct cl_request;

struct node_info_req
{
    node_info_req() : type(INFO_REQ_NONE), intervals(0), wbuf_size(0), wbuf_pos(0), hbuf_pos(0), rbuf(NULL), rbuf_size(0), rbuf_pos(0) {}

    enum node_info_req_type
    {
        INFO_REQ_NONE = 0,
        INFO_REQ_CHECK = 1,
        INFO_REQ_GET_REPLICAS = 2
    };

    // What type of info request is in progress, if any.
    node_info_req_type		type;

    // How many node timer periods this request has lasted.
    uint32_t				intervals;

    // Buffer for writing to socket.
    uint8_t					wbuf[sizeof(cl_proto)+INFO_STR_MAX_LEN];
    size_t					wbuf_size;
    size_t					wbuf_pos;

    // Buffer for reading proto header from socket.
    uint8_t					hbuf[sizeof(cl_proto)];
    size_t					hbuf_pos;

    // Buffer for reading proto body from socket.
    uint8_t*				rbuf;
    size_t					rbuf_size;
    size_t					rbuf_pos;
};


struct cl_cluster_node
{
    cl_cluster_node(ev2citrusleaf_cluster* parent, const char* name);
    ~cl_cluster_node();

    inline void report_success()  { cf_atomic32_incr(&n_successes); }
    inline void report_failure()  { cf_atomic32_incr(&n_failures); }

    aerospike::spinlock     _spinlock;

    // This node's name, a null-terminated hex string.
    char					name[20];

    // A vector of sockaddr_in which the host (node) is currently known by.
    std::vector<sockaddr_in> _sockaddr_in_v;

    // The cluster we belong to.
    ev2citrusleaf_cluster*	asc;

    // How many node timer periods this node has been out of partitions map.
    uint32_t				intervals_absent;

    // Transaction successes & failures since this node's last timer event.
    cf_atomic32				n_successes;
    cf_atomic32				n_failures;

    // This node's recent transaction successes & failures.
    uint32_t				successes[MAX_HISTORY_INTERVALS];
    uint32_t				failures[MAX_HISTORY_INTERVALS];
    uint32_t				current_interval;

    // Rate at which transactions to this node are being throttled.
    cf_atomic32				throttle_pct;

    // Socket pool for (non-info) transactions on this node.
    std::queue<int>         _conn_q;
    //cf_queue*				conn_q;

    // Number of sockets open on this node - for now just for stats.
    cf_atomic32				n_fds_open;

    // What version of partition information we have for this node.
    cf_atomic_int			partition_generation;

    // Socket for info transactions on this node.
    int						info_fd;

    // The info transaction in progress, if any.
    node_info_req			info_req;

    // Space for two events: periodic node timer, and info request.
    uint8_t*			    _event_space;
};

// Must be in-sync with ev2citrusleaf_cluster_runtime_options.
struct threadsafe_runtime_options
{
    threadsafe_runtime_options() : socket_pool_max(0), read_master_only(0), throttle_reads(0), throttle_writes(0), throttle_threshold_failure_pct(0), throttle_window_seconds(0), throttle_factor(0) {}

    cf_atomic32				socket_pool_max;

    cf_atomic32				read_master_only;

    cf_atomic32				throttle_reads;
    cf_atomic32				throttle_writes;

    // These change together under the lock.
    uint32_t				throttle_threshold_failure_pct;
    uint32_t				throttle_window_seconds;
    uint32_t				throttle_factor;

    // For groups of options that need to change together:
    aerospike::spinlock     _spinlock;
};

struct cl_partition
{
    cl_partition() : master(NULL), prole(NULL) {}

    // Mutex to cover master/prole transitions for this partition.
    aerospike::spinlock     _spinlock; // I'm not sure that the spinlock is a good idea here since we're decending in subfunctions (in libevbent) here maybee we should ha a heavier one.

    // Which node, if any, is the master.
    cl_cluster_node*		master;

    // Which node, if any, is the prole.
    // TODO - not ideal for replication factor > 2.
    cl_cluster_node*		prole;
};

struct cl_partition_table
{
    cl_partition_table(const char* ans, size_t nr_of_partitions);
    ~cl_partition_table();

    // The namespace name.
    char					ns[33];
    // For logging - only dump table to log if it changed since last time.
    bool					was_dumped;
    // Space for array of cl_partition objects.
    size_t                  _nr_of_partitions;
    cl_partition*			_partitions;
};

struct host_address
{
    host_address() : port(0xFFFF) {}
    host_address(const std::string& s, uint16_t p) : hostname(s), port(p) {}
    inline bool operator==(const host_address& a) const { return (hostname == a.hostname && port == a.port); }
    std::string hostname;
    uint16_t    port;
};

// Cluster calls
extern void cl_cluster_node_release(cl_cluster_node *cn, const char *msg);
extern void cl_cluster_node_reserve(cl_cluster_node *cn, const char *msg);
extern void cl_cluster_node_put(cl_cluster_node *cn);          // put node back
extern int cl_cluster_node_fd_get(cl_cluster_node *cn);			// get an FD to the node
extern void cl_cluster_node_fd_put(cl_cluster_node *cn, int fd); // put the FD back
extern bool cl_cluster_node_throttle_drop(cl_cluster_node* cn);


// Partition table calls
// --- all these assume the partition lock is held

extern bool cl_partition_table_is_node_present(cl_cluster_node* node);
extern void cl_partition_table_update(cl_cluster_node* node, const char* ns, bool* masters, bool* proles);

struct ev2citrusleaf_cluster
{
    ev2citrusleaf_cluster(event_base *base);
    ~ev2citrusleaf_cluster();


    // Client uses base for internal cluster management events. If NULL is passed,
    // an event base and thread are created internally for cluster management.
    //
    // If NULL opts is passed, ev2citrusleaf_cluster_static_options defaults are
    // used. The opts fields are copied and opts only needs to last for the scope of
    // this call.
    static ev2citrusleaf_cluster* ev2citrusleaf_cluster_create(event_base *base);

    // Before calling ev2citrusleaf_cluster_destroy(), stop initiating transaction
    // requests to this cluster, and make sure that all in-progress transactions are
    // completed, i.e. their callbacks have been made.
    //
    // If a base was passed in ev2citrusleaf_cluster_create(), the app must:
    // - First, exit the base's event loop.
    // - Next, call ev2citrusleaf_cluster_destroy().
    // - Finally, free the base.
    // During ev2citrusleaf_cluster_destroy() the client will re-run the base's
    // event loop to handle all outstanding internal cluster management events.
    static void ev2citrusleaf_cluster_destroy(ev2citrusleaf_cluster *asc);

    // Adding a host to the cluster list which will always be checked for membership
    // As this entire interface is async, the number of hosts in the cluster must be
    // checked with a different, non-blocking, call
    void ev2citrusleaf_cluster_add_host(const char *host, short port, bool recheck_now = true);


    cl_cluster_node*    cluster_node_get(const char *ns, const cf_digest *d, bool write);  // get node from cluster
    cl_cluster_node*    cl_partition_table_get(const char *ns, cl_partition_id pid, bool write);
    cl_partition_table* cl_partition_table_get_by_ns(const char* ns);
    cl_partition_table* cl_partition_table_create(const char* ns);

    int ev2citrusleaf_put(event_base *base, const as_key&, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb);

    int ev2citrusleaf_get(event_base* base, const as_key&, const std::vector<std::string>&, int timeout_ms, ev2citrusleaf_callback cb);
    int ev2citrusleaf_get_all(event_base* base, const as_key&, int timeout_ms, ev2citrusleaf_callback cb);
    int ev2citrusleaf_delete(event_base* base, const as_key&, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb);
    int ev2citrusleaf_operate(event_base* base, const as_key&, const std::vector<ev2citrusleaf_operation>& ops, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb);

    int ev2citrusleaf_put_digest(event_base* base, const char* ns, cf_digest *d, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb);
    int ev2citrusleaf_get_digest(event_base* base, const char* ns, cf_digest* d, const std::vector<std::string>&, int timeout_ms, ev2citrusleaf_callback cb);
    int ev2citrusleaf_get_all_digest(event_base* base, const char* ns, cf_digest *d, int timeout_ms, ev2citrusleaf_callback cb);
    int ev2citrusleaf_delete_digest(event_base* base, const char* ns, cf_digest* d, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb);
    int ev2citrusleaf_operate_digest(event_base* base, const char* ns, cf_digest* d, const std::vector<ev2citrusleaf_operation>& ops, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb);

    std::vector<std::string> get_nodes_names() const;

private:
    static void cluster_timer_fn(evutil_socket_t fd, short event, void *udata);
    cl_cluster_node* cluster_node_get_random();
    void cl_partition_table_destroy_all();
    void cl_partition_table_dump();

public:
    mutable aerospike::spinlock             _spinlock;
    // Seems this flag isn't used, but is set from public API. TODO - deprecate?
    bool					                follow;

    // Cluster management event base, specified by app or internally created.
    event_base*		                        base;

    // Associated cluster management DNS event base.
    evdns_base*		                        dns_base;

    // Cluster-specific functionality options.
    threadsafe_runtime_options				runtime_options;

    // List of host-strings and ports added by the user.
    std::vector<host_address>               _hosts;

    // List of node objects in this cluster.
    std::vector<cl_cluster_node*>   _nodes;
    mutable aerospike::spinlock     _node_v_lock;
    cf_atomic_int			        last_node;

    // If we can't get a node for transactions we internally queue the
    // transactions until nodes become available.
    std::deque<cl_request*>         _request_q;

    // Transactions in progress. Includes transactions in the request queue
    // above (everything needing a callback). No longer used for clean shutdown
    // other than to issue a warning if there are incomplete transactions.
    cf_atomic_int			        requests_in_progress;

    // Internal non-node info requests in progress, used for clean shutdown.
    cf_atomic_int			        pings_in_progress;

    // Number of partitions. Not atomic since it never changes on the server.
    cl_partition_id			         n_partitions;

    // Head of linked list of partition tables (one table per namespace).
    std::vector<cl_partition_table*> _partition_table_v;

    // How many tender timer periods this cluster has lasted.
    uint32_t				         tender_intervals;

    // Statistics for this cluster. (Some are atomic only because the public API
    // can dump the statistics in any thread.)

    // History of nodes in the cluster.
    cf_atomic_int			        n_nodes_created;
    cf_atomic_int			        n_nodes_destroyed;

    // Totals for tender transactions.
    cf_atomic_int			n_ping_successes;
    cf_atomic_int			n_ping_failures;

    // Totals for node info transactions.
    cf_atomic_int			n_node_info_successes;
    cf_atomic_int			n_node_info_failures;
    cf_atomic_int			n_node_info_timeouts;

    // Totals for "ordinary" transactions.
    cf_atomic_int			n_req_successes;
    cf_atomic_int			n_req_failures;
    cf_atomic_int			n_req_timeouts;
    cf_atomic_int			n_req_throttles;
    cf_atomic_int			n_internal_retries;
    cf_atomic_int			n_internal_retries_off_q;

    // Totals for batch transactions.
    cf_atomic_int			n_batch_node_successes;
    cf_atomic_int			n_batch_node_failures;
    cf_atomic_int			n_batch_node_timeouts;

    // Space for cluster tender periodic timer event.
    uint8_t*			    _event_space;
};


//
// a global list of all clusters is interesting sometimes
//
// AKG - only changed in create/destroy, read in print_stats
//extern cf_ll		cluster_ll;


// Do a lookup with this name and port, and add the sockaddr to the
// vector using the unique lookup
extern int cl_lookup_immediate(const char *hostname, short port, struct sockaddr_in *sin);
typedef boost::function<void(int result, const std::vector<sockaddr_in>&)>  cl_lookup_async_fn;
extern int cl_lookup(evdns_base *base, const host_address&, cl_lookup_async_fn cb);


// Count a transaction as a success or failure.
// TODO - add a tag parameter for debugging or detailed stats?


//
extern int citrusleaf_info_host(struct sockaddr_in *sa_in, char *names, char **values, int timeout_ms);
extern int citrusleaf_info_parse_single(char *values, char **value);

extern int citrusleaf_cluster_shutdown();



// should be shared_ptr? to get rid of locking problem when deleting or updating things
std::vector<ev2citrusleaf_cluster*> cl_get_clusters();

