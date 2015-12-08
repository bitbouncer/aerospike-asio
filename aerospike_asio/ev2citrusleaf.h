#pragma once
#ifndef __EV2CITRUSLEAF_H__
#define __EV2CITRUSLEAF_H__

#include <vector>
#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/noncopyable.hpp>

#include <stddef.h>
#include <stdint.h>
#include <boost/uuid/uuid.hpp>
#include <event2/event.h>
#include <event2/dns.h>

#include "citrusleaf/cf_base_types.h"
#include "citrusleaf/cf_digest.h"
#include "citrusleaf/cf_log.h"

#define EV2CITRUSLEAF_OK	0
#define EV2CITRUSLEAF_FAIL_CLIENT_ERROR -1
#define EV2CITRUSLEAF_FAIL_TIMEOUT -2
#define EV2CITRUSLEAF_FAIL_THROTTLED -3
#define EV2CITRUSLEAF_FAIL_UNKNOWN 1
#define EV2CITRUSLEAF_FAIL_NOTFOUND 2
#define EV2CITRUSLEAF_FAIL_GENERATION 3
#define EV2CITRUSLEAF_FAIL_PARAMETER 4
#define EV2CITRUSLEAF_FAIL_KEY_EXISTS 5 // if 'WRITE_ADD', could fail because already exists
#define EV2CITRUSLEAF_FAIL_BIN_EXISTS 6
#define EV2CITRUSLEAF_FAIL_CLUSTER_KEY_MISMATCH 7
#define EV2CITRUSLEAF_FAIL_PARTITION_OUT_OF_SPACE 8
#define EV2CITRUSLEAF_FAIL_SERVERSIDE_TIMEOUT 9 // internal - this is mapped to EV2CITRUSLEAF_FAIL_TIMEOUT
#define EV2CITRUSLEAF_FAIL_NOXDS 10
#define EV2CITRUSLEAF_FAIL_UNAVAILABLE 11
#define EV2CITRUSLEAF_FAIL_INCOMPATIBLE_TYPE 12 // specified operation cannot be performed on that data type
#define EV2CITRUSLEAF_FAIL_RECORD_TOO_BIG 13
#define EV2CITRUSLEAF_FAIL_KEY_BUSY 14
#define EV2CITRUSLEAF_NO_GENERATION 0xFFFFFFFF

std::string aerospike_error_code_to_string(int);

enum ev2citrusleaf_type 
{ 
    CL_NULL = 0x00, 
    CL_INT = 0x01, 
    CL_FLOAT = 2, 
    CL_STR = 0x03, 
    CL_BLOB = 0x04,
	CL_TIMESTAMP = 5, 
    CL_DIGEST = 6, 
    CL_JAVA_BLOB = 7, 
    CL_CSHARP_BLOB = 8, 
    CL_PYTHON_BLOB = 9, 
	CL_RUBY_BLOB = 10, 
    CL_UNKNOWN = 666666
};

typedef enum ev2citrusleaf_type ev2citrusleaf_type;

enum ev2citrusleaf_write_policy 
{ 
    CL_WRITE_ASYNC, 
    CL_WRITE_ONESHOT, 
    CL_WRITE_RETRY, 
    CL_WRITE_ASSURED 
};

typedef enum ev2citrusleaf_write_policy ev2citrusleaf_write_policy;

typedef char ev2citrusleaf_bin_name[32];

//
// An object is the value in a bin, or it is used as a key
// The object is typed according to the citrusleaf typing system
// These are often stack allocated, and are assigned using the 'wrap' calls
//



struct ev2citrusleaf_object
{
    ev2citrusleaf_object();
    ev2citrusleaf_object(const ev2citrusleaf_object&);
    ev2citrusleaf_object& operator=(const ev2citrusleaf_object&);
    ~ev2citrusleaf_object();

    inline void clear()
    {
        if (_free)
            free(_free);
        _free = NULL;
        type = CL_NULL;
    }
    void set_null();
    void assign(const std::string& value);
    void assign(int64_t i);
    void assign_blob(const void *blob, size_t len);
    void assign(boost::shared_ptr<std::vector<uint8_t> > value);  // why not use this as internal rep????



	enum ev2citrusleaf_type    type;
	size_t			           size;
	union 
    {
		char 		*str;   // note for str: size is strlen (not strlen+1 
		void 		*blob;
		int64_t		i64;    // easiest to have one large int type
	} u;

	void* _free; // if this is set, this must be freed on destruction	
} ;

class as_digest
{
public:
    enum { AS_DIGEST_VALUE_SIZE = 20 };
    as_digest() : _is_init(false) {}
    inline bool is_init() const { return _is_init; }
    void init(uint8_t*, size_t len);
    bool _is_init;
    uint8_t _value[AS_DIGEST_VALUE_SIZE];
};


class as_key_object
{
public:
    as_key_object() : type(CL_NULL), _free(NULL) {}
    as_key_object(const as_key_object& k) 
    { 
        type = k.type; 
        size = k.size; 
        _free = NULL;
        switch (type)
        {
        case CL_NULL: break;
        case CL_STR: _free = u.str = strdup(k.u.str);  break;
        case CL_INT: u.i64 = k.u.i64; break;
        case CL_BLOB:  _free = u.blob = malloc(size);  memcpy(u.blob, k.u.blob, size); break;
        default:
            assert(false);
            ;
        };
    }
    const as_key_object& operator=(const as_key_object& k)
    {
        clear();
        type = k.type;
        size = k.size;
        _free = NULL;
        switch (type)
        {
        case CL_NULL: break;
        case CL_STR: _free = u.str = strdup(k.u.str);  break;
        case CL_INT: u.i64 = k.u.i64; break;
        case CL_BLOB:  _free = u.blob = malloc(size);  memcpy(u.blob, k.u.blob, size); break;
        default:
            assert(false);
            ;
        };
        return *this;
    }

    ~as_key_object()   { clear(); }

    inline void clear()
    {
        if (_free)
            free(_free);
        _free = NULL;
        type = CL_NULL;
    }

    void assign(const char *str)
    {
        if (_free)
            free(_free);

        type = CL_STR;
        size = strlen(str);
        _free = u.str = strdup(str);
    }

    void assign(int64_t i)
    {
        if (_free)
            free(_free);

        type = CL_INT;
        size = 8;
        u.i64 = i;
        _free = 0;
    }

    void assign(void *blob, size_t len)
    {
        if (_free)
            free(_free);

        type = CL_BLOB;
        size = len;
        _free = u.blob = malloc(len);
        memcpy(u.blob, blob, len);
    }

    enum ev2citrusleaf_type    type;
    size_t			           size;
    union
    {
        char 		*str;   // note for str: size is strlen (not strlen+1 
        void 		*blob;
        int64_t		i64;    
    } u;

    void* _free; // if this is set, this must be freed on destruction	
};


//a key is 
class as_key
{
public:
    enum { AS_NAMESPACE_MAX_SIZE = 32, AS_SET_MAX_SIZE = 64 };
    as_key() { _ns[0] = '\0';  _set[0] = '\0'; }
    as_key(const as_key& k) { strcpy(_ns, k._ns); strcpy(_set, k._set); _value = k._value; } // make a deep copy WE SHOULD CHECK FOR SELF TBD
    as_key(const char* ns, const char* set, const char* value)  { assign(ns, set, value); }
    as_key(const char* ns, const char* set, uint64_t value) { assign(ns, set, value); }
    as_key(const char* ns, const char* set, const uint8_t* value, size_t len) { assign(ns, set, value, len); }
    as_key(const char* ns, const char* set, const boost::uuids::uuid& uuid) { assign(ns, set, uuid.data, 16); }
    as_key(const std::string& ns, const std::string& set, const boost::uuids::uuid& uuid) { assign(ns, set, uuid.data, 16); }

    void assign(const char* ns, const char* set, const char* value)
    {
        strcpy(_ns, ns); 
        strcpy(_set, set); 
        _value.assign(value);
    }

    void assign(const char* ns, const char* set, uint64_t value)
    {
        strcpy(_ns, ns); 
        strcpy(_set, set); 
        _value.assign(value); 
    }

    void assign(const char* ns, const char* set, const uint8_t* value, size_t len)
    {
        strcpy(_ns, ns);
        strcpy(_set, set);
        _value.assign((void*) value, len);
    }

    void assign(const std::string& ns, const std::string& set, const uint8_t* value, size_t len)
    {
        strncpy(_ns, ns.c_str(), AS_NAMESPACE_MAX_SIZE);
        _ns[AS_NAMESPACE_MAX_SIZE - 1] = '\0';
        strncpy(_set, set.c_str(), AS_SET_MAX_SIZE);
        _set[AS_SET_MAX_SIZE - 1] = '\0';
        _value.assign((void*)value, len);
    }

    void assign(const char* ns, const char* set, const boost::uuids::uuid& uuid)
    {
        strcpy(_ns, ns);
        strcpy(_set, set);
        _value.assign((void*)uuid.data, 16);
    }

    char                 _ns[AS_NAMESPACE_MAX_SIZE];
    char                 _set[AS_SET_MAX_SIZE];
    as_key_object        _value;
};


// A bin is a name and an object

class ev2citrusleaf_bin : public boost::noncopyable
{
public:
    ev2citrusleaf_bin() {}

    ev2citrusleaf_bin(const std::string& s) // NULL type - used for queries
    {
        bin_name = s;
    }

    ev2citrusleaf_bin(const std::string& s, const std::string& value)
    {
        bin_name = s;
        object.assign(value);
    }

    ev2citrusleaf_bin(const std::string& s, const char* str, size_t len)
    {
        bin_name = s;
        object.assign_blob(str, len);
    }
    
    ev2citrusleaf_bin(const std::string& s, const void* value, size_t len)
    {
        bin_name = s;
        object.assign_blob(value, len);
    }

    ev2citrusleaf_bin(const std::string& s, boost::shared_ptr<std::vector<uint8_t> > value)
    {
        bin_name = s;
        object.assign(value);
    }

    ev2citrusleaf_bin(const std::string& s, int64_t value)
    {
        bin_name = s;
        object.assign(value);
    }

    std::string		            bin_name;
	ev2citrusleaf_object		object;
};


class ev2citrusleaf_operation
{
public:
    enum cl_operator_type {
        CL_OP_WRITE, 		// 0
        CL_OP_READ, 		// 1
        CL_OP_INCR, 		// 2
        CL_OP_MC_INCR, 		// 3
        CL_OP_PREPEND, 		// 4
        CL_OP_APPEND, 		// 5
        CL_OP_MC_PREPEND, 	// 6
        CL_OP_MC_APPEND, 	// 7
        CL_OP_TOUCH, 		// 8
        CL_OP_MC_TOUCH		// 9
    };
    std::string		      bin_name;
    cl_operator_type      op;
	ev2citrusleaf_object  object;
};

//
// All citrusleaf functions return an integer. This integer is 0 if the
// call has succeeded, and a negative number if it has failed.
// All returns of pointers and objects are done through the parameters.
// (When in C++, use & parameters for return, but we're not there yet)
//
// 'void' return functions are only used for functions that are syntactically
// unable to fail.
//

//
// ev2citrusleaf_object calls
// 

//void ev2citrusleaf_object_free(ev2citrusleaf_object *o); 
//void ev2citrusleaf_bins_free(ev2citrusleaf_bin *bins, int n_bins);


// Callback to report results of database operations.
//
// If bins array is present, application is responsible for freeing bins'
// objects using ev2citrusleaf_bins_free(), but client will free bins array.
//
// expiration is reported as seconds from now, the time the callback is made.
// (Currently the server returns an epoch-based time which the client converts
// to seconds from now. So if the server's and client's real time clocks are out
// of sync, the reported expiration will be inaccurate. We plan to have the
// server do the conversion, eventually.)


typedef boost::function<void(int ec, std::vector<std::shared_ptr<ev2citrusleaf_bin>>, uint32_t generation, uint32_t expiration)> ev2citrusleaf_callback; // we can use ref here since those must be called in same thread we copy if/when we do a post to another thread

typedef boost::function<void(int ec, uint32_t generation, uint32_t expiration)>                                                  ev2citrusleaf_put_callback;
typedef boost::function<void(int ec, std::vector<std::shared_ptr<ev2citrusleaf_bin>>, uint32_t generation, uint32_t expiration)> ev2citrusleaf_get_callback;
typedef boost::function<void(int ec, uint32_t generation, uint32_t expiration)>                                                  ev2citrusleaf_del_callback;

// Caller may replace client library's mutex calls with these callbacks (e.g. to
// include them in an application monitoring scheme). To use this feature, pass
// a valid ev2citrusleaf_lock_callbacks pointer in ev2citrusleaf_init(). To let
// the client library do its own mutex calls, pass null in ev2citrusleaf_init().
//
// As defined in cf_base/include/citrusleaf/cf_hooks.h:
//
//	typedef struct cf_mutex_hooks_s {
//		// Allocate and initialize new lock.
//		void *(*alloc)(void);
//		// Release all storage held in 'lock'.
//		void (*free)(void *lock);
//		// Acquire an already-allocated lock at 'lock'.
//		int (*lock)(void *lock);
//		// Release a lock at 'lock'.
//		int (*unlock)(void *lock);
//	} cf_mutex_hooks;

//typedef cf_mutex_hooks ev2citrusleaf_lock_callbacks;


/**
  Initialize the asynchronous Citrusleaf library
*/
int ev2citrusleaf_init();

void ev2citrusleaf_shutdown();

//
// This call will print stats to stderr
//
void ev2citrusleaf_print_stats(void);


/**
 * Create a cluster object - all requests are made on a cluster
 */

struct ev2citrusleaf_cluster;

/*
struct ev2citrusleaf_cluster_static_options
{
	// true		- A transaction may specify that its callback be made in a
	//			  different thread from that of the transaction call.
	// false	- Default - A transaction always specifies that its callback be
	//			  made in the same thread as that of the transaction call.
	bool	cross_threaded;
};
*/

struct ev2citrusleaf_cluster_runtime_options
{
	// Per node, the maximum number of open sockets that will be pooled for
	// re-use. Default value is 300. (Note that this does not limit how many
	// sockets can be open at once, just how many are kept for re-use.)
	uint32_t	socket_pool_max;

	// true		- Force all get transactions to read only the master copy.
	// false	- Default - Allow get transactions to read master or replica.
	bool		read_master_only;

	// If transactions to a particular database server node are failing too
	// often, the client can be set to "throttle" transactions to that node by
	// specifying which transactions may be throttled, the threshold failure
	// percentage above which to throttle, and how hard to throttle. Throttling
	// is done by purposefully dropping a certain percentage of transactions
	// (API calls return EV2CITRUSLEAF_FAIL_THROTTLED for dropped transactions)
	// in order to lighten the load on the node.
	//
	// f: actual failure percentage, measured over several seconds
	// t: percentage of transactions to drop
	// t = (f - throttle_threshold_failure_pct) * throttle_factor
	// ... where t is capped at 90%.

	// true		- Allow reads to be throttled.
	// false	- Default - Don't throttle reads.
	bool		throttle_reads;

	// true		- Allow writes to be throttled.
	// false	- Default - Don't throttle writes.
	bool		throttle_writes;

	// Throttle when actual failure percentage exceeds this. Default value is 2.
	uint32_t	throttle_threshold_failure_pct;

	// Measure failure percentage over this interval. Default 15, min 1, max 65.
	uint32_t	throttle_window_seconds;

	// How hard to throttle. Default value is 10.
	uint32_t	throttle_factor;
};



// Get the current cluster runtime options. This will return the default options
// if ev2citrusleaf_cluster_set_options() has never been called. It's for
// convenience - get the current/default values in opts, modify the desired
// field(s), then pass opts in ev2citrusleaf_cluster_set_options().
int ev2citrusleaf_cluster_get_runtime_options(ev2citrusleaf_cluster *asc, ev2citrusleaf_cluster_runtime_options *opts);

// Set/change cluster runtime options. The opts fields are copied and opts only
// needs to last for the scope of this call.
int ev2citrusleaf_cluster_set_runtime_options(ev2citrusleaf_cluster *asc, const ev2citrusleaf_cluster_runtime_options *opts);


// Following is the act of tracking the cluster members as there are changes in
// ownership of the cluster, and load balancing. Following is enabled by default,
// turn it off only for debugging purposes
void ev2citrusleaf_cluster_follow(ev2citrusleaf_cluster *cl, bool flag);

// Gets the number of active nodes
// -1 means the call failed - the cluster object is invalid
// 0 means no nodes - won't get fast response
// more is good!
//
// Warning!  A typical code pattern would be to create the cluster, add a host,
// and loop on this call. That will never succeed, because libevent doesn't
// have an active thread. You will need to give libevent a thread, which is shown
// in the example distributed with this client. Or don't use threads and just
// dispatch.
int ev2citrusleaf_cluster_get_active_node_count(ev2citrusleaf_cluster *cl);

// Returns the number of requests in progress.
// May use this to check that all requests on a cluster are cleared before
// calling ev2citrusleaf_cluster_destroy().
int ev2citrusleaf_cluster_requests_in_progress(ev2citrusleaf_cluster *cl);

// For troubleshooting only - force all nodes in the cluster to refresh their
// partition table information.
void ev2citrusleaf_cluster_refresh_partition_tables(ev2citrusleaf_cluster *cl);


//
// An extended information structure
// when you want to control every little bit of write information you can
//
// Expiration is in *seconds from now*.
//
struct ev2citrusleaf_write_parameters
{
    ev2citrusleaf_write_parameters() :
    use_generation(false),
    generation(0),
    expiration(0),
    wpol(CL_WRITE_RETRY)
    {}

	bool	use_generation;
	uint32_t generation;
	uint32_t expiration;
	ev2citrusleaf_write_policy wpol;
} ;

// If you'd like to start out with default parameters, call this function
/*
static inline void ev2citrusleaf_write_parameters_init(ev2citrusleaf_write_parameters *wparam)
{
	wparam->use_generation = false; // ignore the following generation count
	wparam->generation = 0;
	wparam->expiration = 0; // no per-item expiration
	wparam->wpol = CL_WRITE_RETRY;
}
*/
//
// Get and put calls
//

//
// Batch calls
//

// An array of these is returned via ev2citrusleaf_get_many_cb.
//
// result will be either EV2CITRUSLEAF_OK or EV2CITRUSLEAF_FAIL_NOTFOUND.
//
// For the result of a ev2citrusleaf_exists_many_digest() call, bins and n_bins
// will always be NULL and 0 respectively.
//
// For the result of a ev2citrusleaf_get_many_digest() call, if result is
// EV2CITRUSLEAF_OK bin data will be present. Application is responsible for
// freeing bins' objects using ev2citrusleaf_bins_free(), but client will free
// bins array.

struct ev2citrusleaf_rec
{
	int					result;			// result for this record
	cf_digest			digest;			// digest identifying record
	uint32_t			generation;		// record generation
	uint32_t			expiration;		// record expiration, seconds from now
	ev2citrusleaf_bin*  bins;			// record data - array of bins
	int					n_bins;			// number of bins in bins array
};

// Batch-get callback, to report results of ev2citrusleaf_get_many_digest() and
// ev2citrusleaf_exists_many_digest() calls.
//
// result is "overall" result - may be OK while individual record results are
// EV2CITRUSLEAF_FAIL_NOTFOUND. Typically not OK when batch job times out or one
// or more nodes' transactions fail. In all failure cases partial record results
// may be returned, therefore n_recs may be less than n_digests requested.
//
// recs is the array of individual record results. Client will free recs array.
// n_recs is the number of records in recs array.
//
// The order of records in recs array does not necessarily correspond to the
// order of digests in request.

typedef boost::function<void(int result, ev2citrusleaf_rec *recs, int n_recs)> ev2citrusleaf_get_many_cb;

// Get a batch of records, specified by array of digests.
//
// Pass NULL bins, 0 n_bins, to get all bins. (Note - bin name filter not yet
// supported by server - pass NULL, 0.)
//
// If return value is EV2CITRUSLEAF_OK, the callback will always be made. If
// not, the callback will not be made.

int ev2citrusleaf_get_many_digest(ev2citrusleaf_cluster *cl, const char *ns, const cf_digest *digests, int n_digests, const char **bins, int n_bins, int timeout_ms, ev2citrusleaf_get_many_cb cb, struct event_base *base);

// Check existence of a batch of records, specified by array of digests.
//
// If return value is EV2CITRUSLEAF_OK, the callback will always be made. If
// not, the callback will not be made.

int ev2citrusleaf_exists_many_digest(ev2citrusleaf_cluster *cl, const char *ns, const cf_digest *digests, int n_digests, int timeout_ms, ev2citrusleaf_get_many_cb cb, struct event_base *base);


//
// the info interface allows
// information about specific cluster features to be retrieved on a host by host basis
// size_t is in number of bytes. String is null terminated as well
// API CONTRACT: *callee* frees the 'response' buffer
typedef boost::function<void(int return_value, char *response, size_t response_len)> ev2citrusleaf_info_callback;

int ev2citrusleaf_info(event_base *base, evdns_base *dns_base, char *host, short port, char *names, int timeout_ms, ev2citrusleaf_info_callback cb);

//
// This debugging call can be useful for tracking down errors and coordinating with server failures
//
int ev2citrusleaf_calculate_digest(const char *set, const ev2citrusleaf_object *key, cf_digest *digest);

#endif

