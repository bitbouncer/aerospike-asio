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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <event2/dns.h>
#include <event2/event.h>
#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_base_types.h"
#include "citrusleaf/cf_byte_order.h"
#include "citrusleaf/cf_clock.h"
#include "citrusleaf/cf_digest.h"
#include "citrusleaf/cf_errno.h"
#include "citrusleaf/cf_log_internal.h"
#include "citrusleaf/cf_socket.h"
#include "citrusleaf/proto.h"

#include "cl_cluster.h"
#include "ev2citrusleaf.h"
#include "ev2citrusleaf-internal.h"

ev2citrusleaf_object::ev2citrusleaf_object() : type(CL_NULL), _free(NULL), size(0)
{
    //std::cerr << "create " << this << std::endl;
}

ev2citrusleaf_object::ev2citrusleaf_object(const ev2citrusleaf_object& a) : type(a.type), _free(NULL), size(a.size)
{
    //std::cerr << "create CC " << this << std::endl;
    // integers or NULL
    if (!a._free)
    {
        u.i64 = a.u.i64;
        return;
    }

    if (type == CL_STR)
    {
        _free = u.str = (char*) malloc(size + 1);
        strncpy(u.str, a.u.str, size);
        u.str[size] = '\0';
    }
    else
    {
        _free = u.blob = (char*)malloc(size + 1);
        memcpy(u.blob, a.u.blob, size);
    }
}

ev2citrusleaf_object& ev2citrusleaf_object::operator=(const ev2citrusleaf_object& a)
{
    if (this == &a)
        return *this;
     
    clear();
    type = a.type;
    size = a.size;
    
    // integers or NULL
    if (!a._free)
    {
        u.i64 = a.u.i64;
        return *this;;
    }

    if (type == CL_STR)
    {
        _free = u.str = (char*)malloc(size + 1);
        strncpy(u.str, a.u.str, size);
        u.str[size] = '\0';
    }
    else
    {
        _free = u.blob = (char*)malloc(size + 1);
        memcpy(u.blob, a.u.blob, size);
    }
   
    return *this;
}

ev2citrusleaf_object::~ev2citrusleaf_object()
{
    //std::cerr << "delete " << this << std::endl;
    clear();
}

void
ev2citrusleaf_object::set_null()
{
    if (_free)
        free(_free);
    type = CL_NULL;
    size = 0;
    _free = NULL;
    u.i64 = 0;
}

void
ev2citrusleaf_object::assign(const std::string& value)
{
    if (_free)
        free(_free);

    type = CL_STR;
    size = value.size();
    _free = u.str = (char*) malloc(size+1);
    memcpy(u.str, value.data(), size);
    u.str[size] = '\0';
}

void
ev2citrusleaf_object::assign(int64_t i)
{
    if (_free)
        free(_free);

    type = CL_INT;
    size = 8;
    u.i64 = i;
    _free = 0;
}

void
ev2citrusleaf_object::assign_blob(const void *blob, size_t len)
{
    if (_free)
        free(_free);

    type = CL_BLOB;
    size = len;
    _free = u.blob = malloc(len);
    memcpy(u.blob, blob, len);
}


void ev2citrusleaf_object::assign(boost::shared_ptr<std::vector<uint8_t> > value)
{
    if (_free)
        free(_free);

    type = CL_BLOB;
    size = value->size();
    _free = u.blob = malloc(size);
    memcpy(u.blob, &value->front(), size);
}

//
// Debug calls for printing the buffers. Very useful for debugging....
//
#if 0
static void
dump_buf(char *info, uint8_t *buf, size_t buf_len)
{
    if (cf_debug_enabled()) {
        char msg[buf_len * 4 + 2];
        char* p = msg;

        strcpy(p, "dump_buf: ");
        p += 10;
        strcpy(p, info);
        p += strlen(info);

        for (uint i = 0; i < buf_len; i++) {
            if (i % 16 == 8) {
                *p++ = ' ';
                *p++ = ':';
            }
            if (i && (i % 16 == 0)) {
                *p++ = '\n';
            }
            sprintf(p, "%02x ", buf[i]);
            p += 3;
        }

        *p = 0;
        cf_debug(msg);
    }
}
#endif


//
// Forward reference
//
bool ev2citrusleaf_restart(cl_request* req, bool may_throttle);


//
// Buffer formatting calls
//

uint8_t*
cl_write_header(uint8_t* buf, size_t msg_size, int info1, int info2,
uint32_t generation, uint32_t expiration, uint32_t timeout,
uint32_t n_fields, uint32_t n_ops)
{
    as_msg *msg = (as_msg *)buf;
    msg->proto.version = CL_PROTO_VERSION;
    msg->proto.type = CL_PROTO_TYPE_CL_MSG;
    msg->proto.sz = msg_size - sizeof(cl_proto);
    cl_proto_swap(&msg->proto);
    msg->m.header_sz = sizeof(cl_msg);
    msg->m.info1 = info1;
    msg->m.info2 = info2;
    msg->m.info3 = 0;  // info3 never currently written
    msg->m.unused = 0;
    msg->m.result_code = 0;
    msg->m.generation = generation;
    msg->m.record_ttl = expiration;
    msg->m.transaction_ttl = timeout;
    msg->m.n_fields = n_fields;
    msg->m.n_ops = n_ops;
    cl_msg_swap_header(&msg->m);
    return (buf + sizeof(as_msg));
}


//
// cl_request
//
cl_request::cl_request(ev2citrusleaf_cluster* aasc, struct event_base* abase, int atimeout_ms, const ev2citrusleaf_write_parameters* wparam, ev2citrusleaf_callback cb) :
fd(-1),
base(abase),
asc(aasc),
node(NULL),
timeout_ms(atimeout_ms),
wpol(wparam ? wparam->wpol : CL_WRITE_RETRY),
user_cb(cb),
write(false),
wr_buf(NULL),
wr_buf_pos(0),
wr_buf_size(0),
rd_header_pos(0),
rd_buf(NULL),
rd_buf_pos(0),
rd_buf_size(0),
network_set(0),
timeout_set(0),
base_hop_set(0),
start_time(0),
_event_space(NULL)
{
    ns[0] = '\0';
    memset(&d, 0, sizeof(d));
    _event_space = new uint8_t[2 * event_get_struct_event_size()];
}

cl_request::~cl_request()
{
    if (wr_buf_size && wr_buf != wr_tmp) {
        free(wr_buf);
    }

    if (rd_buf_size && rd_buf != rd_tmp) {
        free(rd_buf);
    }

    delete[] _event_space;
    _event_space = NULL;
}

struct event *
    cl_request_get_network_event(cl_request *r)
{
        return((struct event *) &r->_event_space[0]);
    }

struct event *
    cl_request_get_timeout_event(cl_request *r)
{
        return((struct event *) &r->_event_space[event_get_struct_event_size()]);
    }

//
// lay out a request into a buffer
// Caller is encouraged to allocate some stack space for something like this
// buf if the space isn't big enough we'll malloc
//
// FIELDS WILL BE SWAPED INTO NETWORK ORDER

static uint8_t* write_fields(uint8_t* buf, const char* ns, int ns_len, const char* set, int set_len, const as_key_object* key, const cf_digest* d, cf_digest* d_ret)
{
    // lay out the fields
    cl_msg_field *mf = (cl_msg_field *)buf;
    cl_msg_field *mf_tmp;

    mf->type = CL_MSG_FIELD_TYPE_NAMESPACE;
    mf->field_sz = ns_len + 1;
    memcpy(mf->data, ns, ns_len);
    mf_tmp = cl_msg_field_get_next(mf);
    cl_msg_swap_field(mf);
    mf = mf_tmp;

    if (set) {
        mf->type = CL_MSG_FIELD_TYPE_SET;
        mf->field_sz = set_len + 1;
        memcpy(mf->data, set, set_len);
        mf_tmp = cl_msg_field_get_next(mf);
        cl_msg_swap_field(mf);
        mf = mf_tmp;
    }

    if (key) {
        mf->type = CL_MSG_FIELD_TYPE_KEY;
        // make a function call here, similar to our prototype code in the server
        if (key->type == CL_STR) {
            mf->field_sz = (uint32_t)key->size + 2;
            uint8_t *fd = (uint8_t *)&mf->data;
            fd[0] = CL_PARTICLE_TYPE_STRING;
            memcpy(&fd[1], key->u.str, key->size);
        }
        else if (key->type == CL_BLOB) {
            mf->field_sz = (uint32_t)key->size + 2;
            uint8_t *fd = (uint8_t *)&mf->data;
            fd[0] = CL_PARTICLE_TYPE_BLOB;
            memcpy(&fd[1], key->u.blob, key->size);
        }
        else if (key->type == CL_INT) {
            mf->field_sz = sizeof(int64_t)+2;
            uint8_t *fd = (uint8_t *)&mf->data;
            fd[0] = CL_PARTICLE_TYPE_INTEGER;
            uint64_t swapped = htonll((uint64_t)key->u.i64);
            memcpy(&fd[1], &swapped, sizeof(swapped));
        }
        else {
            AEROSPIKE_WARN << "unknown citrusleaf type " << key->type;
            return(0);
        }
        mf_tmp = cl_msg_field_get_next(mf);
        cl_msg_swap_field(mf);
    }

    if (d_ret && key)
        cf_digest_compute2(set, set_len, mf->data, key->size + 1, d_ret);

    if (d) {
        mf->type = CL_MSG_FIELD_TYPE_DIGEST_RIPE;
        mf->field_sz = sizeof(cf_digest)+1;
        memcpy(mf->data, d, sizeof(cf_digest));
        mf_tmp = cl_msg_field_get_next(mf);
        cl_msg_swap_field(mf);
        if (d_ret)
            memcpy(d_ret, d, sizeof(cf_digest));

        mf = mf_tmp;

    }


    return ((uint8_t *)mf_tmp);
}

// Convert the int value to the wire protocol

int
value_to_op_int(int64_t value, uint8_t *data)
{
    if ((value < 0) || (value >= 0x7FFFFFFF)) {
        *(uint64_t*)data = htonll((uint64_t)value);  // swap in place
        return(8);
    }

    if (value <= 0x7F) {
        *data = (uint8_t)value;
        return(1);
    }

    if (value <= 0x7FFF) {
        *(uint16_t *)data = htons((uint16_t)value);
        return(2);
    }

    // what remains is 4 byte representation
    *(uint32_t *)data = htonl((uint32_t)value);
    return(4);
}


extern int
ev2citrusleaf_calculate_digest(const char *set, const ev2citrusleaf_object *key, cf_digest *digest)
{
    int set_len = set ? (int)strlen(set) : 0;

    // make the key as it's laid out for digesting
    // THIS IS A STRIPPED DOWN VERSION OF THE CODE IN write_fields ABOVE
    // MUST STAY IN SYNC!!!
    uint8_t* k = (uint8_t*)alloca(key->size + 1);
    switch (key->type) {
    case CL_STR:
        k[0] = key->type;
        memcpy(&k[1], key->u.str, key->size);
        break;
    case CL_INT:
    {
                   uint64_t swapped;
                   k[0] = key->type;
                   swapped = htonll((uint64_t)key->u.i64);
                   memcpy(&k[1], &swapped, sizeof(swapped)); // THIS MUST LEAD TO A WRONG LENGTH CALCULATION BELOW
    }
        break;
    case CL_BLOB:
    case CL_JAVA_BLOB:
    case CL_CSHARP_BLOB:
    case CL_PYTHON_BLOB:
    case CL_RUBY_BLOB:
        k[0] = key->type;
        memcpy(&k[1], key->u.blob, key->size);
        break;
    default:
        AEROSPIKE_WARN << "transmit key: unknown citrusleaf type " << key->type;
        return(-1);
    }

    cf_digest_compute2((char *)set, set_len, k, key->size + 1, digest);

    return(0);
}

// Get the size of the wire protocol value
// Must match previous function EXACTLY

int
value_to_op_int_size(int64_t i)
{
    if (i < 0)	return(8);
    if (i <= 0x7F)  return(1);
    if (i < 0x7FFF) return(2);
    if (i < 0x7FFFFFFF) return(4);
    return(8);
}


// convert a wire protocol integer value to a local int64
int
op_to_value_int(const uint8_t *buf, int size, int64_t *value)
{
    if (size > 8)	return(-1);
    if (size == 8) {
        // no need to worry about sign extension - blast it
        *value = (int64_t)ntohll(*(uint64_t*)buf);
        return(0);
    }
    if (size == 0) {
        *value = 0;
        return(0);
    }
    if (size == 1 && *buf < 0x7f) {
        *value = *buf;
        return(0);
    }

    // negative numbers must be sign extended; yuck
    if (*buf & 0x80) {
        uint8_t	lg_buf[8];
        int i;
        for (i = 0; i < 8 - size; i++)	lg_buf[i] = 0xff;
        memcpy(&lg_buf[i], buf, size);
        *value = (int64_t)ntohll((uint64_t)*buf);
        return(0);
    }
    // positive numbers don't
    else {
        int64_t	v = 0;
        for (int i = 0; i < size; i++, buf++) {
            v <<= 8;
            v |= *buf;
        }
        *value = v;
        return(0);
    }


    return(0);
}

int
value_to_op_get_size(const ev2citrusleaf_object *v, size_t *sz)
{

    switch (v->type) {
    case CL_NULL:
        break;
    case CL_INT:
        *sz += value_to_op_int_size(v->u.i64);
        break;
    case CL_STR:
        *sz += v->size;
        break;
    case CL_PYTHON_BLOB:
    case CL_RUBY_BLOB:
    case CL_JAVA_BLOB:
    case CL_CSHARP_BLOB:
    case CL_BLOB:
        *sz += v->size;
        break;
    default:
        AEROSPIKE_WARN << "internal error value_to_op get size has unknown value type " << v->type;
        return(-1);
    }
    return(0);
}

void
bin_to_op(int operation, const ev2citrusleaf_bin *v, cl_msg_op *op)
{
    size_t	bin_len = v->bin_name.size();
    op->op_sz = (uint32_t)(sizeof(cl_msg_op)+bin_len - sizeof(uint32_t));
    op->op = operation;
    op->version = 0;
    op->name_sz = (uint8_t)bin_len;
    memcpy(op->name, v->bin_name.data(), bin_len);

    // read operations are very simple because you don't have to copy the body
    if (operation == CL_MSG_OP_READ) {
        op->particle_type = 0; // reading - it's unknown
    }
    // write operation - must copy the value
    else {
        uint8_t *data = cl_msg_op_get_value_p(op);
        switch (v->object.type) {
        case CL_NULL:
            op->particle_type = CL_PARTICLE_TYPE_NULL;
            break;
        case CL_INT:
            op->particle_type = CL_PARTICLE_TYPE_INTEGER;
            op->op_sz += value_to_op_int(v->object.u.i64, data);
            break;
        case CL_STR:
            op->op_sz += (uint32_t)v->object.size;
            op->particle_type = CL_PARTICLE_TYPE_STRING;
            memcpy(data, v->object.u.str, v->object.size);
            break;
        case CL_BLOB:
            op->op_sz += (uint32_t)v->object.size;
            op->particle_type = CL_PARTICLE_TYPE_BLOB;
            memcpy(data, v->object.u.blob, v->object.size);
            break;
        default:
            AEROSPIKE_WARN << "internal error value_to_op has unknown value type " << v->object.type;
            return;
        }
    }

}

void
operation_to_op(const ev2citrusleaf_operation *v, cl_msg_op *op)
{
    size_t	bin_len = v->bin_name.size();
    op->op_sz = (uint32_t)(sizeof(cl_msg_op)+bin_len - sizeof(uint32_t));
    op->name_sz = (uint8_t)bin_len;
    memcpy(op->name, v->bin_name.data(), bin_len);

    // convert. would be better to use a table or something.
    switch (v->op) {
    case ev2citrusleaf_operation::CL_OP_WRITE:
        op->op = CL_MSG_OP_WRITE;
        break;
    case ev2citrusleaf_operation::CL_OP_READ:
        op->op = CL_MSG_OP_READ;
        break;
    case ev2citrusleaf_operation::CL_OP_INCR:
        op->op = CL_MSG_OP_INCR;
        break;
    default:
        assert(false); // op not implented yet...
    }

    // read operations are very simple because you don't have to copy the body
    if (v->op == ev2citrusleaf_operation::CL_OP_READ)
    {
        op->particle_type = 0; // reading - it's unknown
    }
    // write operation - must copy the value
    else {
        uint8_t *data = cl_msg_op_get_value_p(op);
        switch (v->object.type) {
        case CL_NULL:
            op->particle_type = CL_PARTICLE_TYPE_NULL;
            break;
        case CL_INT:
            op->particle_type = CL_PARTICLE_TYPE_INTEGER;
            op->op_sz += value_to_op_int(v->object.u.i64, data);
            break;
        case CL_STR:
            op->op_sz += (uint32_t)v->object.size;
            op->particle_type = CL_PARTICLE_TYPE_STRING;
            memcpy(data, v->object.u.str, v->object.size);
            break;
        case CL_BLOB:
            op->op_sz += (uint32_t)v->object.size;
            op->particle_type = CL_PARTICLE_TYPE_BLOB;
            memcpy(data, v->object.u.blob, v->object.size);
            break;
        default:
            AEROSPIKE_WARN << "internal error value_to_op has unknown value type " << v->object.type;
            return;
        }
    }

}


//
// n_values can be passed in 0, and then values is undefined / probably 0.
//
static int
compile(
int info1, 
int info2, 
const char* ns, 
const char* set,
const as_key_object* key, 
const cf_digest* digest,
const ev2citrusleaf_write_parameters* wparam, 
uint32_t timeout,
std::vector<std::shared_ptr<ev2citrusleaf_bin>> values, 
uint8_t** buf_r,
size_t* buf_size_r, 
cf_digest* digest_r)
{
    // I hate strlen
    int		ns_len = (int)strlen(ns);
    int		set_len = set ? (int)strlen(set) : 0;

    // determine the size
    size_t	msg_size = sizeof(as_msg); // header
    // fields
    if (ns) msg_size += ns_len + sizeof(cl_msg_field);
    if (set) msg_size += set_len + sizeof(cl_msg_field);
    if (key) msg_size += sizeof(cl_msg_field)+1 + key->size;
    if (digest) msg_size += sizeof(cl_msg_field)+1 + sizeof(cf_digest);
    // ops
    for (std::vector<std::shared_ptr<ev2citrusleaf_bin>>::const_iterator i = values.begin(); i != values.end(); ++i)
    {
        msg_size += sizeof(cl_msg_op)+(*i)->bin_name.size();
        if (info2 & CL_MSG_INFO2_WRITE) 
        {
            if (0 != value_to_op_get_size(&(*i)->object, &msg_size)) 
            {
                AEROSPIKE_WARN << "bad operation, writing with unknown type";
                return(-1);
            }
        }
    }

    // size too small? malloc!
    uint8_t	*buf;
    uint8_t *mbuf = 0;
    if ((*buf_r) && (msg_size > *buf_size_r)) 
    {
        mbuf = buf = (uint8_t*)malloc(msg_size);
        if (!buf) 			return(-1);
        *buf_r = buf;
    }
    else
        buf = *buf_r;
    *buf_size_r = msg_size;

    // lay out the header
    uint32_t generation;
    uint32_t expiration;
    if (wparam) {
        if (wparam->use_generation) 
        {
            info2 |= CL_MSG_INFO2_GENERATION;
            generation = wparam->generation;
        }
        else generation = 0;
        expiration = wparam->expiration;
    }
    else {
        generation = expiration = 0;
    }

    int n_fields = (ns ? 1 : 0) + (set ? 1 : 0) + (key ? 1 : 0) + (digest ? 1 : 0);
    buf = cl_write_header(buf, msg_size, info1, info2, generation, expiration, timeout, n_fields, (uint32_t)values.size());

    // now the fields
    buf = write_fields(buf, ns, ns_len, set, set_len, key, digest, digest_r);
    if (!buf) {
        if (mbuf)	free(mbuf);
        return(-1);
    }

    // lay out the ops
    if (values.size())
    {
        int operation = (info2 & CL_MSG_INFO2_WRITE) ? CL_MSG_OP_WRITE : CL_MSG_OP_READ;

        cl_msg_op *op = (cl_msg_op *)buf;
        cl_msg_op *op_tmp;
        for (std::vector<std::shared_ptr<ev2citrusleaf_bin>>::const_iterator i = values.begin(); i != values.end(); ++i)
        {
            bin_to_op(operation, &(**i), op);
            op_tmp = cl_msg_op_get_next(op);
            cl_msg_swap_op(op);
            op = op_tmp;
        }
    }
    return(0);
}

//
// A different version of the compile function which takes operations, not values
// The operation is compiled by looking at the internal ops
//
static int
compile_ops(const char* ns, const char* set, const as_key_object* key,
const cf_digest* digest, const std::vector<ev2citrusleaf_operation>& ops,
const ev2citrusleaf_write_parameters* wparam, uint8_t** buf_r,
size_t* buf_size_r, cf_digest* digest_r, bool* write)
{
    int info1 = 0;
    int info2 = 0;

    // I hate strlen
    int		ns_len = (int)strlen(ns);
    int		set_len = (int)strlen(set);

    // determine the size
    size_t	msg_size = sizeof(as_msg); // header
    // fields
    if (ns) msg_size += ns_len + sizeof(cl_msg_field);
    if (set) msg_size += set_len + sizeof(cl_msg_field);
    if (key) msg_size += sizeof(cl_msg_field)+1 + key->size;
    if (digest) msg_size += sizeof(cl_msg_field)+1 + sizeof(cf_digest);

    // ops
    for (std::vector<ev2citrusleaf_operation>::const_iterator i = ops.begin(); i != ops.end(); ++i)
    {
        msg_size += sizeof(cl_msg_op)+i->bin_name.size();
        if ((i->op == ev2citrusleaf_operation::CL_OP_WRITE) || (i->op == ev2citrusleaf_operation::CL_OP_INCR))
        {
            value_to_op_get_size(&(i->object), &msg_size);
            info2 |= CL_MSG_INFO2_WRITE;
        }
        if (i->op == ev2citrusleaf_operation::CL_OP_READ)
        {
            info1 |= CL_MSG_INFO1_READ;
        }
    }
    if (write) { *write = info2 & CL_MSG_INFO2_WRITE ? true : false; }

    // size too small? malloc!
    uint8_t	*buf;
    uint8_t *mbuf = 0;
    if ((*buf_r) && (msg_size > *buf_size_r)) {
        mbuf = buf = (uint8_t*)malloc(msg_size);
        if (!buf) 			return(-1);
        *buf_r = buf;
    }
    else
        buf = *buf_r;
    *buf_size_r = msg_size;

    // lay out the header
    uint32_t generation;
    uint32_t expiration;
    if (wparam) {
        if (wparam->use_generation) {
            info2 |= CL_MSG_INFO2_GENERATION;
            generation = wparam->generation;
        }
        else generation = 0;
        expiration = wparam->expiration;
    }
    else {
        generation = expiration = 0;
    }

    int n_fields = (ns ? 1 : 0) + (set ? 1 : 0) + (key ? 1 : 0) + (digest ? 1 : 0);
    buf = cl_write_header(buf, msg_size, info1, info2, generation, expiration, expiration, n_fields, (uint32_t) ops.size());

    // now the fields
    buf = write_fields(buf, ns, ns_len, set, set_len, key, digest, digest_r);
    if (!buf) {
        if (mbuf)	free(mbuf);
        return(-1);
    }

    // lay out the ops
    cl_msg_op *op = (cl_msg_op *)buf;
    cl_msg_op *op_tmp;
    for (std::vector<ev2citrusleaf_operation>::const_iterator i = ops.begin(); i != ops.end(); ++i)
    {
        operation_to_op(&(*i), op);
        op_tmp = cl_msg_op_get_next(op);
        cl_msg_swap_op(op);
        op = op_tmp;
    }
    return(0);
}

//
// since we are not copying values here we need the cl_msg_op to be valid until we are done using the object
//
//
// 0 if OK, -1 if fail

int
set_object(cl_msg_op *op, ev2citrusleaf_object *obj)
{
    obj->clear();

    int64_t val = 0;
    switch (op->particle_type) 
    {
    case CL_PARTICLE_TYPE_NULL:
        obj->set_null();
        break;

    case CL_PARTICLE_TYPE_INTEGER:
        op_to_value_int(cl_msg_op_get_value_p(op), cl_msg_op_get_value_sz(op), &val);
        obj->assign(val);
        break;

    case CL_PARTICLE_TYPE_STRING:
        obj->assign(std::string((const char*) cl_msg_op_get_value_p(op), cl_msg_op_get_value_sz(op)));
        break;

        //
    case CL_PARTICLE_TYPE_BLOB:
    case CL_PARTICLE_TYPE_JAVA_BLOB:
    case CL_PARTICLE_TYPE_CSHARP_BLOB:
    case CL_PARTICLE_TYPE_PYTHON_BLOB:
    case CL_PARTICLE_TYPE_RUBY_BLOB:
        obj->assign_blob((const void*)cl_msg_op_get_value_p(op), cl_msg_op_get_value_sz(op));
        break;

    default:
        AEROSPIKE_WARN << "received unknown object type " << op->particle_type;
        return(-1);
    }
    return(0);
}

//
// Search through the value list and set the pre-existing correct one
// Leads ot n-squared in this section of code
// See other comment....
int
set_value_search(cl_msg_op *op, ev2citrusleaf_bin *values, int n_values)
{
    // currently have to loop through the values to find the right one
    // how that sucks! it's easy to fix eventuallythough
    int i;
    for (i = 0; i < n_values; i++)
    {
        if (memcmp(values[i].bin_name.data(), op->name, op->name_sz) == 0)
            break;
    }
    if (i == n_values) {
        AEROSPIKE_WARN << "set value: but value wasn't there to begin with. Don't understand.";
        return(-1);
    }

    // copy
    set_object(op, &values[i].object);
    return(0);
}


//
// Copy this particular operation to that particular value
void
cl_set_value_particular(cl_msg_op *op, ev2citrusleaf_bin *value)
{
    if (op->name_sz > sizeof(value->bin_name)) {
        AEROSPIKE_WARN << "Set Value Particular: bad response from server";
        return;
    }

    // svante value->bin_name.swap(std::string((const char*)op->name, op->name_sz));
    value->bin_name = std::string((const char*)op->name, op->name_sz);
    set_object(op, &value->object);
}


int
parse_get_maxbins(uint8_t *buf, size_t buf_len)
{
    cl_msg	*msg = (cl_msg *)buf;
    return (ntohs(msg->n_ops));
}

//
// parse the incoming response buffer, copy the incoming ops into the values array passed in
// which has been pre-allocated on the stack by the caller and will be passed to the
// callback routine then auto-freed stack style
//
// The caller is allows to pass values_r and n_values_r as NULL if it doesn't want those bits
// parsed out.
//
// Unlike some of the read calls, the msg contains all of its data, contiguous
// And has been swapped?

int parse(uint8_t *buf, size_t buf_len, std::vector<std::shared_ptr<ev2citrusleaf_bin>>* values, int *result_code, uint32_t *generation, uint32_t *p_expiration)
{
    int i;
    cl_msg	*msg = (cl_msg *)buf;
    uint8_t *limit = buf + buf_len;
    buf += sizeof(cl_msg);

    cl_msg_swap_header(msg);

    *result_code = msg->result_code;
    *generation = msg->generation;
    *p_expiration = cf_server_void_time_to_ttl(msg->record_ttl);

    if (msg->n_fields) 
    {
        cl_msg_field *mf = (cl_msg_field *)buf;
        for (i = 0; i < msg->n_fields; i++) 
        {

            if ((uint8_t *)mf >= limit) 
            {
                AEROSPIKE_WARN << "poorly formatted response: fail";
                return(-1);
            }

            cl_msg_swap_field(mf);
            mf = cl_msg_field_get_next(mf);
        }
        buf = (uint8_t *)mf;
    }

    cl_msg_op *op = (cl_msg_op *)buf;

    // if you're interested in the values at all
    if (values==NULL)
        return(0);

    // copy all incoming values into the newly allocated structure
    for (i = 0; i < msg->n_ops; i++) 
    {
        if ((uint8_t *)op >= limit) 
        {
            AEROSPIKE_WARN << "poorly formatted response2";
            return(-1);
        }

        cl_msg_swap_op(op);
        
        switch (op->particle_type) 
        {
            case CL_PARTICLE_TYPE_NULL:
                values->emplace_back(std::make_shared<ev2citrusleaf_bin>(std::string((const char*)op->name, op->name_sz)));
                break;

            case CL_PARTICLE_TYPE_INTEGER:
                int64_t val;
                op_to_value_int(cl_msg_op_get_value_p(op), cl_msg_op_get_value_sz(op), &val);
                values->emplace_back(std::make_shared<ev2citrusleaf_bin>(std::string((const char*)op->name, op->name_sz), val));
                break;

            case CL_PARTICLE_TYPE_STRING:
                values->emplace_back(std::make_shared<ev2citrusleaf_bin>(std::string((const char*)op->name, op->name_sz), std::string((const char*)cl_msg_op_get_value_p(op), cl_msg_op_get_value_sz(op))));
                break;

            case CL_PARTICLE_TYPE_BLOB:
            case CL_PARTICLE_TYPE_JAVA_BLOB:
            case CL_PARTICLE_TYPE_CSHARP_BLOB:
            case CL_PARTICLE_TYPE_PYTHON_BLOB:
            case CL_PARTICLE_TYPE_RUBY_BLOB:
                values->emplace_back(std::make_shared<ev2citrusleaf_bin>(std::string((const char*)op->name, op->name_sz), (const void*)cl_msg_op_get_value_p(op), cl_msg_op_get_value_sz(op)));
                break;
            default:
                AEROSPIKE_WARN << "received unknown object type " << op->particle_type;
                return(-1);
        }

        //ev2citrusleaf_bin val;
        //cl_set_value_particular(op, &val);
        //values->push_back(val);
        op = cl_msg_op_get_next(op);
    }
    return 0;
}


void
ev2citrusleaf_request_complete(cl_request *req, bool timedout)
{
    //	dump_buf("request complete :", req->rd_buf, req->rd_buf_size);

    if (req->timeout_set) {
        evtimer_del(cl_request_get_timeout_event(req));
    }

    // critical to close this before the file descriptor associated, for some
    // reason
    if (req->network_set) {
        event_del(cl_request_get_network_event(req));
    }

    // Reuse or close the socket, if it's open.
    if (req->fd > -1) {
        if (req->node) {
            if (!timedout) {
                cl_cluster_node_fd_put(req->node, req->fd);
            }
            else {
                cf_close(req->fd);
                cf_atomic32_decr(&req->node->n_fds_open);
            }

            req->fd = -1;
        }
        else {
            // Since we can't assert:
            AEROSPIKE_ERROR << "request has open fd but null node";
        }
    }

    if (timedout == false) {

        std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins;
        bins.reserve(parse_get_maxbins(req->rd_buf, req->rd_buf_size));

        // parse up into the response
        int			return_code;
        uint32_t	generation;
        uint32_t	expiration;

        parse(req->rd_buf, req->rd_buf_size, &bins, &return_code, &generation, &expiration);

        // For simplicity & backwards-compatibility, convert server-side
        // timeouts to the usual timeout return-code:
        if (return_code == EV2CITRUSLEAF_FAIL_SERVERSIDE_TIMEOUT)
        {
            return_code = EV2CITRUSLEAF_FAIL_TIMEOUT;
            AEROSPIKE_DEBUG << "server-side timeout";
        }

        // Call the callback
        req->user_cb(return_code, bins, generation, expiration);

        if (req->node) {
            switch (return_code) {
                // TODO - any other server return codes to consider as failures?
            case EV2CITRUSLEAF_FAIL_TIMEOUT:
                req->node->report_failure();
                cf_atomic_int_incr(&req->asc->n_req_timeouts);
                cf_atomic_int_incr(&req->asc->n_req_failures);
                break;
            default:
                req->node->report_success();
                cf_atomic_int_incr(&req->asc->n_req_successes);
                break;
            }
        }
        else {
            // Since we can't assert:
            AEROSPIKE_ERROR << "request succeeded but has null node";
        }
    }

    else {
        // timedout

        // could still be in the cluster's pending queue. Scrub it out.
        //MUTEX_LOCK(req->asc->request_q_lock);

        // inefficient removal of simething in the middle ???
        req->asc->_request_q.erase(std::remove(req->asc->_request_q.begin(), req->asc->_request_q.end(), req), req->asc->_request_q.end());
        //cf_queue_delete(req->asc->request_q, &req, true /*onlyone*/);
        //MUTEX_UNLOCK(req->asc->request_q_lock);

        // If the request had been popped from the queue, base-hopped, and
        // activated (so it's about to be processed after this event) we need to
        // delete it. Note - using network event slot for base-hop event.
        if (req->base_hop_set)
            event_del(cl_request_get_network_event(req));

        // call with a timeout specifier
        //std::vector<ev2citrusleaf_bin> empty_bins;
        (req->user_cb) (EV2CITRUSLEAF_FAIL_TIMEOUT, {}, 0, 0);

        if (req->node)
            req->node->report_failure();

        // The timeout will be counted in the timer callback - we also get here
        // on transaction failures that don't do an internal retry.
        cf_atomic_int_incr(&req->asc->n_req_failures);
    }

    // Release the node.
    if (req->node) {
        cl_cluster_node_put(req->node);
        req->node = 0;
    }

    cf_atomic_int_decr(&req->asc->requests_in_progress);

    delete req;
}

//
// A quick non-blocking check to see if a server is connected. It may have
// dropped my connection while I'm queued, so don't use those connections
//
// if the fd is connected, we actually expect an error - ewouldblock or similar
//
int
ev2citrusleaf_is_connected(int fd)
{
    uint8_t buf[8];
    int rv = recv(fd, (cf_socket_data_t*)buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT | MSG_NOSIGNAL);
    if (rv == 0) {
        AEROSPIKE_DEBUG << "connected check: found disconnected fd " << fd;
        return(CONNECTED_NOT);
    }

    if (rv < 0) {
        if (cf_errno() == EBADF) {
            AEROSPIKE_WARN << "connected check: EBADF fd " << fd;
            return(CONNECTED_BADFD);
        }
        else if ((cf_errno() == EWOULDBLOCK) || (cf_errno() == EAGAIN)) {
            return(CONNECTED);
        }
        else {
            AEROSPIKE_INFO << "connected check: fd " << fd << " error " << cf_errno();
            return(CONNECTED_ERROR);
        }
    }

    return(CONNECTED);
}


//
// Got an event on one of our file descriptors. DTRT.
// NETWORK EVENTS ONLY
void
ev2citrusleaf_event(evutil_socket_t fd, short event, void *udata)
{
    cl_request *req = (cl_request*)udata;

    int rv;

    uint64_t _s = cf_getms();

    //event_cross_thread_check(req);

    req->network_set = false;

    if (event & EV_WRITE) {
        if (req->wr_buf_pos < req->wr_buf_size) {
            rv = send(fd, (cf_socket_data_t*)&req->wr_buf[req->wr_buf_pos], (cf_socket_size_t)(req->wr_buf_size - req->wr_buf_pos), MSG_DONTWAIT | MSG_NOSIGNAL);

            if (rv > 0) {
                req->wr_buf_pos += rv;
                if (req->wr_buf_pos == req->wr_buf_size) {
                    event_assign(cl_request_get_network_event(req), req->base, fd, EV_READ, ev2citrusleaf_event, req);
                }
            }
            // according to man, send never returns 0. But do we trust it?
            else if (rv == 0) {
                AEROSPIKE_DEBUG << "ev2citrusleaf_write failed with 0, posix not followed: fd " << fd << " rv " << rv << " errno " << cf_errno();
                goto Fail;
            }
            else if ((cf_errno() != EAGAIN) && (cf_errno() != EWOULDBLOCK)) 
            {
                AEROSPIKE_DEBUG << "ev2citrusleaf_write failed: fd " << fd << " rv " << rv << " errno " << cf_errno();
                goto Fail;
            }

        }
    }

    if (event & EV_READ) {
        if (req->rd_header_pos < sizeof(cl_proto)) {
            rv = recv(fd, (cf_socket_data_t*)&req->rd_header_buf[req->rd_header_pos], (cf_socket_size_t)(sizeof(cl_proto)-req->rd_header_pos), MSG_DONTWAIT | MSG_NOSIGNAL);

            if (rv > 0) {
                req->rd_header_pos += rv;
            }
            else if (rv == 0) {
                // connection has been closed by the server. A normal occurrance, perhaps.
                AEROSPIKE_DEBUG << "ev2citrusleaf read2: connection closed: fd " << fd << " rv " << rv << " errno " << cf_errno();
                goto Fail;
            }
            else {
                if ((cf_errno() != EAGAIN) && (cf_errno() != EWOULDBLOCK)) {
                    AEROSPIKE_DEBUG << "read failed: rv " << rv << " errno " << cf_errno();
                    goto Fail;
                }
            }
        }

        if (req->rd_header_pos == sizeof(cl_proto)) {
            // initialize the read buffer
            if (req->rd_buf_size == 0) {
                // calculate msg size
                cl_proto *proto = (cl_proto *)req->rd_header_buf;
                cl_proto_swap(proto);

                // set up the read buffer
                if (proto->sz <= sizeof(req->rd_tmp))
                    req->rd_buf = req->rd_tmp;
                else {
                    req->rd_buf = (uint8_t*)malloc(proto->sz);
                    if (!req->rd_buf) {
                        AEROSPIKE_ERROR << "malloc fail";
                        goto Fail;
                    }
                }
                req->rd_buf_pos = 0;
                req->rd_buf_size = proto->sz;
            }
            if (req->rd_buf_pos < req->rd_buf_size) {
                rv = recv(fd, (cf_socket_data_t*)&req->rd_buf[req->rd_buf_pos], (cf_socket_size_t)(req->rd_buf_size - req->rd_buf_pos), MSG_DONTWAIT | MSG_NOSIGNAL);

                if (rv > 0) {
                    req->rd_buf_pos += rv;
                    if (req->rd_buf_pos == req->rd_buf_size) {
                        ev2citrusleaf_request_complete(req, false); // frees the req
                        req = 0;
                        return;
                    }
                }
                else if (rv == 0) {
                    // connection has been closed by the server. Errno is invalid. A normal occurrance, perhaps.
                    AEROSPIKE_DEBUG << "ev2citrusleaf read2: connection closed: fd " << fd << " rv " << rv << " errno " << cf_errno();
                    goto Fail;
                }
                else if ((cf_errno() != EAGAIN) && (cf_errno() != EWOULDBLOCK)) {
                    AEROSPIKE_DEBUG << "ev2citrusleaf read2: fail: fd " << fd << " rv " << rv << " errno " << cf_errno();
                    goto Fail;
                }
            }
        }
        else {
            AEROSPIKE_DEBUG << "ev2citrusleaf event: received read while not expecting fd " << fd;
        }
    }

    if (req) {
        if (0 == event_add(cl_request_get_network_event(req), 0 /*timeout*/)) {
            req->network_set = true;
        }
        else req->network_set = false;
    }
    
    {
        uint64_t delta = cf_getms() - _s;
        if (delta > CL_LOG_DELAY_INFO)
        {
            AEROSPIKE_INFO << "event took " << delta;
        }
    }
    return;

Fail:
    cf_close(fd);
    req->fd = -1;

    if (req->node) {
        cf_atomic32_decr(&req->node->n_fds_open);
    }
    else {
        // Since we can't assert:
        AEROSPIKE_ERROR << "request network event has null node";
    }

    if (req->wpol == CL_WRITE_ONESHOT) {
        AEROSPIKE_INFO << "write oneshot with network error";
        // So far we're not distinguishing whether the failure was a local or
        // remote problem. It will be treated as remote and counted against the
        // node for throttle-control purposes.
        ev2citrusleaf_request_complete(req, true);
    }
    else {
        AEROSPIKE_DEBUG << "ev2citrusleaf failed a request, calling restart";

        if (req->node) {
            cl_cluster_node_put(req->node);
            req->node = 0;
        }
        // else - already "asserted".

        cf_atomic_int_incr(&req->asc->n_internal_retries);
        ev2citrusleaf_restart(req, false);
    }
    {
        uint64_t  delta = cf_getms() - _s;
        if (delta > CL_LOG_DELAY_INFO)
        {
            AEROSPIKE_INFO << "event fail took " << delta;
        }
    }
}

//
// A timer has gone off on a request
// fd is not set

void
ev2citrusleaf_timer_expired(evutil_socket_t fd, short event, void *udata)
{
    cl_request *req = (cl_request*)udata;
    uint64_t _s = cf_getms();
    req->timeout_set = false;
    cf_atomic_int_incr(&req->asc->n_req_timeouts);
    ev2citrusleaf_request_complete(req, true /*timedout*/); // frees the req
    uint64_t delta = cf_getms() - _s;
    if (delta > CL_LOG_DELAY_INFO)
    {
        AEROSPIKE_INFO << "CL_DELAY: timer expired took " << delta;
    }
}


static void
ev2citrusleaf_base_hop_event(evutil_socket_t fd, short event, void *udata)
{
    cl_request* req = (cl_request*)udata;
    //event_cross_thread_check(req);
    req->base_hop_set = false;
    AEROSPIKE_DEBUG << "have node now, restart request " << req;
    cf_atomic_int_incr(&req->asc->n_internal_retries_off_q);
    ev2citrusleaf_restart(req, false);
}


void
ev2citrusleaf_base_hop(cl_request *req)
{
    // We'll use the unused network event slot.
    event_assign(cl_request_get_network_event(req), req->base, -1, 0, ev2citrusleaf_base_hop_event, req);

    if (0 != event_add(cl_request_get_network_event(req), 0))
    {
        AEROSPIKE_WARN << "unable to add base-hop event for request " << req << " will time out";
        return;
    }

    req->base_hop_set = true;

    // Tell the event to fire on the appropriate base ASAP.
    event_active(cl_request_get_network_event(req), 0, 0);
}


// Return values:
// true  - success, or will time out, or queued for internal retry
// false - throttled
bool
ev2citrusleaf_restart(cl_request* req, bool may_throttle)
{
    // If we've already timed out, don't bother adding the network event, just
    // let the timeout event (which no doubt is about to fire) clean up.
    if (req->timeout_ms > 0 && req->start_time + req->timeout_ms < cf_getms()) {
        return true;
    }

    // Set/reset state to beginning of transaction.
    req->wr_buf_pos = 0;
    req->rd_buf_pos = 0;
    req->rd_header_pos = 0;

    // Sanity checks.
    if (req->node) 
    {
        AEROSPIKE_ERROR << "req has node " << req->node->name << " on restart";
    }

    if (req->fd != -1) 
    {
        AEROSPIKE_ERROR << "req has fd " << req->fd << " on restart";
    }

    req->node = 0;
    req->fd = -1;

    cl_cluster_node* node;
    int fd;
    int i;

    for (i = 0; i < 5; i++)
    {
        node = req->asc->cluster_node_get(req->ns, &req->d, req->write);

        if (!node)
        {
            req->asc->_request_q.push_back(req);
            return true;
        }

        // Throttle before bothering to get the socket.
        if (may_throttle && cl_cluster_node_throttle_drop(node)) {
            // Randomly dropping this transaction in order to throttle.
            cf_atomic_int_incr(&req->asc->n_req_throttles);
            cl_cluster_node_put(node);
            return false;
        }

        fd = -1;

        while (fd == -1) {
            fd = cl_cluster_node_fd_get(node);
        }

        if (fd > -1) {
            // Got a good socket.
            break;
        }

        // Couldn't get a socket, try again from scratch. Probably we'll get the
        // same node, but for normal reads or if we got a random node we could
        // get a different node.
        cl_cluster_node_put(node);
    }

    // Safety - don't retry from scratch forever.
    if (i == 5)
    {
        AEROSPIKE_INFO << "request restart loop quit after 5 tries";
        req->asc->_request_q.push_back(req);
        return true;
    }

    // Go ahead, using the good node and socket.
    req->node = node;
    req->fd = fd;

    event_assign(cl_request_get_network_event(req), req->base, fd, EV_WRITE,
        ev2citrusleaf_event, req);

    req->network_set = true;

    if (0 != event_add(cl_request_get_network_event(req), 0 /*timeout*/)) {
        AEROSPIKE_WARN << "unable to add event for request " << req << " will time out";
        req->network_set = false;
    }

    return true;
}


void
start_failed(cl_request* req)
{
    if (!req->timeout_set) {
        delete req;
        return;
    }
    event_del(cl_request_get_timeout_event(req));
    delete req;
}

//
// Omnibus internal function used by public transactions API.
//
int
ev2citrusleaf_start(cl_request* req, int info1, int info2, const char* ns, const char* set, const as_key_object* key, const cf_digest* digest, const ev2citrusleaf_write_parameters* wparam, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins)
{
    if (!req)
    {
        return EV2CITRUSLEAF_FAIL_CLIENT_ERROR;
    }
    // To implement timeout, add timer event in parallel to network event chain.
    if (req->timeout_ms) {
        if (req->timeout_ms < 0) {
            AEROSPIKE_WARN << "timeout < 0";
            delete req;
            return EV2CITRUSLEAF_FAIL_CLIENT_ERROR;
        }

        if (req->timeout_ms > 1000 * 60) {
            AEROSPIKE_INFO << "timeout > 60 seconds";
        }

        evtimer_assign(cl_request_get_timeout_event(req), req->base,
            ev2citrusleaf_timer_expired, req);

        struct timeval tv;
        tv.tv_sec = req->timeout_ms / 1000;
        tv.tv_usec = (req->timeout_ms % 1000) * 1000;

        if (0 != evtimer_add(cl_request_get_timeout_event(req), &tv)) {
            AEROSPIKE_WARN << "request add timer failed";
            delete req;
            return EV2CITRUSLEAF_FAIL_CLIENT_ERROR;
        }

        req->timeout_set = true;
    }
    // else there's no timeout - supported, but a bit dangerous.

    req->start_time = cf_getms();
    req->wr_buf = req->wr_tmp;
    req->wr_buf_size = sizeof(req->wr_tmp);
    req->write = (info2 & CL_MSG_INFO2_WRITE) ? true : false;
    strcpy(req->ns, ns);

    // Fill out the request write buffer.
    if (0 != compile(
        info1, 
        info2, 
        ns, 
        set, 
        key, 
        digest, 
        wparam,
        req->timeout_ms, 
        bins, 
        &req->wr_buf, 
        &req->wr_buf_size,
        &req->d)) 
    {
        start_failed(req);
        return EV2CITRUSLEAF_FAIL_CLIENT_ERROR;
    }

    //	dump_buf("sending request to cluster:", req->wr_buf, req->wr_buf_size);

    // Determine whether we may throttle.
    bool may_throttle = req->write ?
        cf_atomic32_get(req->asc->runtime_options.throttle_writes) != 0 :
        cf_atomic32_get(req->asc->runtime_options.throttle_reads) != 0;

    // Initial restart - get node and socket and initiate network event chain.
    if (!ev2citrusleaf_restart(req, may_throttle)) {
        start_failed(req);
        return EV2CITRUSLEAF_FAIL_THROTTLED;
    }
    cf_atomic_int_incr(&req->asc->requests_in_progress);
    return EV2CITRUSLEAF_OK;
}


//
// Internal function used by public operate transaction API.
//
int ev2citrusleaf_start_op(cl_request* req, const char* ns, const char* set, const as_key_object* key, const cf_digest* digest, const std::vector<ev2citrusleaf_operation>& ops, const ev2citrusleaf_write_parameters* wparam)
{
    if (!req)
        return EV2CITRUSLEAF_FAIL_CLIENT_ERROR;

    // To implement timeout, add timer event in parallel to network event chain.
    if (req->timeout_ms) {
        if (req->timeout_ms < 0) {
            AEROSPIKE_WARN << "timeout < 0";
            delete req;
            return EV2CITRUSLEAF_FAIL_CLIENT_ERROR;
        }

        if (req->timeout_ms > 1000 * 60) {
            AEROSPIKE_INFO << "timeout > 60 seconds";
        }

        evtimer_assign(cl_request_get_timeout_event(req), req->base,
            ev2citrusleaf_timer_expired, req);

        struct timeval tv;
        tv.tv_sec = req->timeout_ms / 1000;
        tv.tv_usec = (req->timeout_ms % 1000) * 1000;

        if (0 != evtimer_add(cl_request_get_timeout_event(req), &tv)) {
            AEROSPIKE_WARN << "request add timer failed";
            delete req;
            return EV2CITRUSLEAF_FAIL_CLIENT_ERROR;
        }

        req->timeout_set = true;
    }
    // else there's no timeout - supported, but a bit dangerous.

    req->start_time = cf_getms();
    req->wr_buf = req->wr_tmp;
    req->wr_buf_size = sizeof(req->wr_tmp);
    strcpy(req->ns, ns);

    // Fill out the request write buffer.
    if (0 != compile_ops(ns, set, key, digest, ops, wparam, &req->wr_buf,
        &req->wr_buf_size, &req->d, &req->write)) {
        start_failed(req);
        return EV2CITRUSLEAF_FAIL_CLIENT_ERROR;
    }

    //	dump_buf("sending request to cluster:", req->wr_buf, req->wr_buf_size);

    // Initial restart - get node and socket and initiate network event chain.
    if (!ev2citrusleaf_restart(req, false)) {
        start_failed(req);
        return EV2CITRUSLEAF_FAIL_THROTTLED;
    }
    cf_atomic_int_incr(&req->asc->requests_in_progress);
    return EV2CITRUSLEAF_OK;
}

//
// head functions
//

int
ev2citrusleaf_cluster::ev2citrusleaf_get_all(event_base *base, const as_key& key, int timeout_ms, ev2citrusleaf_callback cb)
{
    cl_request* req = new  cl_request(this, base, timeout_ms, NULL, cb);
    return ev2citrusleaf_start(req, CL_MSG_INFO1_READ | CL_MSG_INFO1_GET_ALL, 0, key._ns, key._set, &key._value, 0/*digest*/, 0, {});
}

int
ev2citrusleaf_cluster::ev2citrusleaf_put(event_base *base, const as_key& key, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb)
{
    cl_request* req = new  cl_request(this, base, timeout_ms, wparam, cb);
    return ev2citrusleaf_start(req, 0, CL_MSG_INFO2_WRITE, key._ns, key._set, &key._value, 0/*digest*/, wparam, bins);
}

int
ev2citrusleaf_cluster::ev2citrusleaf_get(event_base *base, const as_key& key, const std::vector<std::string>& bins_names, int timeout_ms, ev2citrusleaf_callback cb)
{
    std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins;
    bins.reserve(bins_names.size());
    for (std::vector<std::string>::const_iterator i = bins_names.begin(); i != bins_names.end(); ++i)
        bins.emplace_back(std::make_shared<ev2citrusleaf_bin>(*i));

    cl_request* req = new  cl_request(this, base, timeout_ms, NULL, cb);
    return ev2citrusleaf_start(req, CL_MSG_INFO1_READ, 0, key._ns, key._set, &key._value, 0/*digest*/, 0, bins);
}

int
ev2citrusleaf_cluster::ev2citrusleaf_delete(event_base *base, const as_key& key, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb)
{
    cl_request* req = new  cl_request(this, base, timeout_ms, wparam, cb);
    return ev2citrusleaf_start(req, 0, CL_MSG_INFO2_WRITE | CL_MSG_INFO2_DELETE, key._ns, key._set, &key._value, 0/*digest*/, wparam, {});
}

int
ev2citrusleaf_cluster::ev2citrusleaf_operate(event_base* base, const as_key& key, const std::vector<ev2citrusleaf_operation>& ops, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb)
{
    cl_request* req = new  cl_request(this, base, timeout_ms, wparam, cb);
    return ev2citrusleaf_start_op(req, key._ns, key._set, &key._value, 0/*digest*/, ops, wparam);
}


int
ev2citrusleaf_cluster::ev2citrusleaf_get_all_digest(event_base *base, const char *ns, cf_digest *digest, int timeout_ms, ev2citrusleaf_callback cb)
{
    cl_request* req = new  cl_request(this, base, timeout_ms, NULL, cb);
    return ev2citrusleaf_start(req, CL_MSG_INFO1_READ | CL_MSG_INFO1_GET_ALL, 0, ns, 0/*set*/, 0/*key*/, digest, 0, {});
}


int
ev2citrusleaf_cluster::ev2citrusleaf_put_digest(event_base *base, const char *ns, cf_digest *digest, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb)
{
    cl_request* req = new  cl_request(this, base, timeout_ms, wparam, cb);
    return ev2citrusleaf_start(req, 0, CL_MSG_INFO2_WRITE, ns, 0/*set*/, 0/*key*/, digest, wparam, bins);
}


int
ev2citrusleaf_cluster::ev2citrusleaf_get_digest(event_base *base, const char* ns, cf_digest* digest, const std::vector<std::string>& bin_names, int timeout_ms, ev2citrusleaf_callback cb)
{
    std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins;
    bins.reserve(bin_names.size());
    for (std::vector<std::string>::const_iterator i = bin_names.begin(); i != bin_names.end(); ++i)
        bins.emplace_back(std::make_shared<ev2citrusleaf_bin>(*i));

    cl_request* req = new  cl_request(this, base, timeout_ms, NULL, cb);
    return ev2citrusleaf_start(req, CL_MSG_INFO1_READ, 0, ns, 0/*set*/, 0/*key*/, digest, 0, bins);
}

int
ev2citrusleaf_cluster::ev2citrusleaf_delete_digest(event_base *base, const char *ns, cf_digest *digest, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb)
{
    cl_request* req = new  cl_request(this, base, timeout_ms, wparam, cb);
    return ev2citrusleaf_start(req, 0, CL_MSG_INFO2_WRITE | CL_MSG_INFO2_DELETE, ns, 0/*set*/, 0/*key*/, digest, wparam, {});
}


int
ev2citrusleaf_cluster::ev2citrusleaf_operate_digest(event_base* base, const char *ns, cf_digest *digest, const std::vector<ev2citrusleaf_operation>& ops, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb)
{
    cl_request* req = new  cl_request(this, base, timeout_ms, wparam, cb);
    return ev2citrusleaf_start_op(req, ns, 0/*set*/, 0/*key*/, digest, ops, wparam);
}

bool g_ev2citrusleaf_initialized = false;

int ev2citrusleaf_init()
{
    if (g_ev2citrusleaf_initialized) 
    {
        AEROSPIKE_INFO << "citrusleaf: init called twice, benign";
        return(0);
    }

    g_ev2citrusleaf_initialized = true;

    extern const char *citrusleaf_build_string;
    AEROSPIKE_INFO << "Aerospike client version " << citrusleaf_build_string;

    memset((void*)&g_cl_stats, 0, sizeof(g_cl_stats));

    srand(cf_clepoch_seconds());

    return(0);
}

// TODO - get rid of unused param at next API change.
void
ev2citrusleaf_shutdown()
{
    citrusleaf_cluster_shutdown();
    g_ev2citrusleaf_initialized = false;
}


//==========================================================
// Statistics
//

cl_statistics g_cl_stats;

void
cluster_print_stats(ev2citrusleaf_cluster* asc)
{
    return;

    // Match with the log level below.
    if (!cf_info_enabled()) {
        return;
    }

    uint32_t n_nodes = 0;
    uint32_t n_fds_open = 0;
    uint32_t n_fds_pooled = 0;

    // Collect per-node info.
    {
        aerospike::spinlock::scoped_lock xxx(asc->_node_v_lock);
        n_nodes = (uint32_t)asc->_nodes.size();
        for (std::vector<cl_cluster_node*>::const_iterator i = asc->_nodes.begin(); i != asc->_nodes.end(); ++i)
        {
            n_fds_open += cf_atomic32_get((*i)->n_fds_open);
            n_fds_pooled += (int)(*i)->_conn_q.size();
        }
    }
    // Most of the stats below are cf_atomic_int, and should be accessed with
    // cf_atomic_int_get(), but since I know that's a no-op wrapper I'm being
    // lazy and leaving the code below as-is -- AKG.

    // Global (non cluster-related) stats first.
    AEROSPIKE_INFO << "stats :: global ::";
    AEROSPIKE_INFO << "      :: app-info " << g_cl_stats.app_info_requests;

    // Cluster stats.
    AEROSPIKE_INFO << "stats :: cluster " << asc;
    AEROSPIKE_INFO << "      :: nodes : created " << asc->n_nodes_created << " destroyed:" << asc->n_nodes_destroyed << " current " << n_nodes;
    AEROSPIKE_INFO << "      :: tend-pings : success " << asc->n_ping_successes << " fail " << asc->n_ping_failures;
    AEROSPIKE_INFO << "      :: node-info-reqs : success " << asc->n_node_info_successes << " fail " << asc->n_node_info_failures << " timeout " << asc->n_node_info_timeouts;
    AEROSPIKE_INFO << "      :: reqs : success " << asc->n_req_successes << " fail " << asc->n_req_failures << " timeout " << asc->n_req_timeouts << " throttle " << asc->n_req_throttles << " in-progress " << asc->requests_in_progress;
    //AEROSPIKE_INFO << "      :: req-retries : direct " << asc->n_internal_retries << " off - q " << asc->n_internal_retries_off_q << " : on - q " << (int)asc->_request_q.size();
    //AEROSPIKE_INFO << "      :: batch-node-reqs : success %lu fail %lu timeout %lu", asc->n_batch_node_successes, asc->n_batch_node_failures, asc->n_batch_node_timeouts);
    AEROSPIKE_INFO << "      :: fds : open " << n_fds_open << " pooled " << n_fds_pooled;
}

// TODO - deprecate cluster list and add cluster param to this API call?
void ev2citrusleaf_print_stats()
{
    std::vector<ev2citrusleaf_cluster*> clusters = cl_get_clusters();
    for (auto i = clusters.begin(); i != clusters.end(); ++i)
        cluster_print_stats(*i);
}

std::string aerospike_error_code_to_string(int ec)
{
    switch (ec)
    {
    case EV2CITRUSLEAF_OK: return "aerospike::success (no error)";
    case EV2CITRUSLEAF_FAIL_CLIENT_ERROR: return "aerospike::FAIL_CLIENT_ERROR";
    case EV2CITRUSLEAF_FAIL_TIMEOUT: return "aerospike::FAIL_TIMEOUT";
    case EV2CITRUSLEAF_FAIL_THROTTLED: return "aerospike::FAIL_THROTTLED";
    case EV2CITRUSLEAF_FAIL_UNKNOWN: return "aerospike::FAIL_UNKNOWN";
    case EV2CITRUSLEAF_FAIL_NOTFOUND: return "aerospike::FAIL_NOTFOUN";
    case EV2CITRUSLEAF_FAIL_GENERATION: return "aerospike::FAIL_GENERATION";
    case EV2CITRUSLEAF_FAIL_PARAMETER: return "aerospike::FAIL_PARAMETER";
    case EV2CITRUSLEAF_FAIL_KEY_EXISTS: return "aerospike::FAIL_KEY_EXISTS";
    case EV2CITRUSLEAF_FAIL_BIN_EXISTS: return "aerospike::FAIL_BIN_EXISTS";
    case EV2CITRUSLEAF_FAIL_CLUSTER_KEY_MISMATCH: return "aerospike::FAIL_CLUSTER_KEY_MISMATCH";
    case EV2CITRUSLEAF_FAIL_PARTITION_OUT_OF_SPACE: return "aerospike::FAIL_PARTITION_OUT_OF_SPACE";
    case EV2CITRUSLEAF_FAIL_SERVERSIDE_TIMEOUT: return "aerospike::FAIL_SERVERSIDE_TIMEOUT";
    case EV2CITRUSLEAF_FAIL_NOXDS: return "aerospike::FAIL_NOXDS";
    case EV2CITRUSLEAF_FAIL_UNAVAILABLE: return "aerospike::FAIL_UNAVAILABLE";
    case EV2CITRUSLEAF_FAIL_INCOMPATIBLE_TYPE: return "aerospike::FAIL_INCOMPATIBLE_TYPE";
    case EV2CITRUSLEAF_FAIL_RECORD_TOO_BIG: return "aerospike::FAIL_RECORD_TOO_BIG";
    case EV2CITRUSLEAF_FAIL_KEY_BUSY: return "aerospike::FAIL_KEY_BUSY";
    default:
        return "aerospike::FAIL unknown error_code:" + std::to_string(ec);
    };
}