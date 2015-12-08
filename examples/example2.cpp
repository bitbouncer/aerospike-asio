#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/thread.hpp>
#include <aerospike_asio/aerospike_asio.h>

#include <aerospike_asio/ev2citrusleaf.h>
#include <aerospike_asio/cl_cluster.h>

const char DEFAULT_HOST[] = "192.168.0.144";
const int DEFAULT_PORT = 3000;
//const char DEFAULT_NAMESPACE[] = "mqtt";
const char DEFAULT_NAMESPACE[] = "mem";
const char DEFAULT_SET[] = "test-set";
const int DEFAULT_TRIGGER_USEC = 2000;
const int DEFAULT_TIMEOUT_MSEC = 200;
const int DEFAULT_NUM_BASES = 32;
const int DEFAULT_NUM_KEYS = 1000 * 16;

const char BIN_NAME[] = "test-bin-name";

const int CLUSTER_VERIFY_TRIES = 5;
const uint64_t CLUSTER_VERIFY_INTERVAL = 1000 * 1000; // 1 second


//==========================================================
// Typedefs
//

struct config
{
    std::string   host;
    int           port;
    std::string   ns;
    std::string   set;
    int           trigger_usec;
    int           timeout_msec;
    int           num_bases;
    int           num_keys;
};

struct base 
{
    base() : num_put_timeouts(0), num_get_timeouts(0), num_not_found(0) {}
    uint32_t           num_put_timeouts;
    uint32_t           num_get_timeouts;
    uint32_t           num_not_found;
};

//==========================================================
// Globals
//

static config                 g_config;
static base*                  g_bases = NULL;
static as_key*                g_keys = NULL;
static ev2citrusleaf_write_parameters g_write_parameters;

static bool set_config();
static void usage();



//==========================================================
// Transaction Operations
//
static void get(aerospike::cluster* cluster, int shard, int key, int key_begin, int key_end);
static void validate_data(int b, int k, const std::vector<std::shared_ptr<ev2citrusleaf_bin>>& bins);

//------------------------------------------------
// Start a database write operation.
//
static void put(aerospike::cluster* cluster, int shard, int key, int key_begin, int key_end)
{
    cluster->put(
        g_keys[key],		        	// key of record to write
        { std::make_shared<ev2citrusleaf_bin>(BIN_NAME, key) },// bin (array) to write
        g_write_parameters,			    // write parameters
        g_config.timeout_msec,			// transaction timeout
        [cluster, shard, key, key_begin, key_end](int ec, uint32_t generation, uint32_t expiration)
    {
        switch (ec) 
        {
        case EV2CITRUSLEAF_OK:
            break;
        case EV2CITRUSLEAF_FAIL_TIMEOUT:
            BOOST_LOG_TRIVIAL(trace) << "PUT TIMEOUT: shard " << shard<< ", key " << key;
            g_bases[shard].num_put_timeouts++;
            // Otherwise ok... Likely leads to EV2CITRUSLEAF_FAIL_NOTFOUND on get.
            break;
        default:
            BOOST_LOG_TRIVIAL(error) << "ec " << ec << " shard " << shard << ", key " << key;
            break;
        }

        if (key+1 != key_end)
        {
            //not done yet
            put(cluster, shard, key + 1, key_begin, key_end);
        }
        else
        {
            BOOST_LOG_TRIVIAL(info) << "shard " << shard << " - done puts[" << g_bases[shard].num_put_timeouts << " timeouts]";
            // Done with the write phase on this base, start the read phase.
            get(cluster, shard, key_begin, key_begin, key_end);
        }
    });
}

//------------------------------------------------
// Start a database read operation.
//
static void get(aerospike::cluster* cluster, int shard, int key, int key_begin, int key_end)
{
    cluster->get_all(
        g_keys[key],				    // key of record to get
        g_config.timeout_msec,			// transaction timeout
        [cluster, shard, key, key_begin, key_end](int return_value, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, uint32_t generation, uint32_t expiration)
    {
        switch (return_value)
        {
        case EV2CITRUSLEAF_OK:
            // Not 100% sure we only get bins if return value is OK. TODO - check.
            validate_data(shard, key, bins);
            // Invalid data will log complaints, but won't exit event loop.
            break;

        case EV2CITRUSLEAF_FAIL_TIMEOUT:
            BOOST_LOG_TRIVIAL(trace) << "GET TIMEOUT: shard " << shard << ", key " << key;
            g_bases[shard].num_get_timeouts++;
            // Otherwise ok...
            break;

        case EV2CITRUSLEAF_FAIL_NOTFOUND:
            BOOST_LOG_TRIVIAL(trace) << "GET NOT FOUND: shard " << shard << ", key " << key;
            g_bases[shard].num_not_found++;
            // Otherwise ok...
            break;

        default:
            BOOST_LOG_TRIVIAL(error) << "return-value " << return_value << " shard " << shard << ", key " << key;
            // Won't exit event loop.
            break;
        }

        if (key + 1 != key_end)
        {
            //not done yet
            get(cluster, shard, key + 1, key_begin, key_end);
        }
        else
        {
            BOOST_LOG_TRIVIAL(info) << "shard " << shard << " - done gets[" << g_bases[shard].num_put_timeouts << " timeouts]";
            // Done with the write phase on this base, start the read phase.
            put(cluster, shard, key_begin, key_begin, key_end);
            //get(cluster, shard, key_begin, key_begin, key_end);
        }
    });
}

//==========================================================
// Main
//

int
main()
{
    boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::trace);
    //Use default Citrusleaf client logging, but set a filter.
    cf_set_log_level(CF_INFO);

    // Parse command line arguments.
    if (!set_config())
        exit(-1);

    boost::asio::io_service fg_ios;
    boost::asio::io_service bg_ios;
    std::auto_ptr<boost::asio::io_service::work> work2(new boost::asio::io_service::work(fg_ios));
    std::auto_ptr<boost::asio::io_service::work> work1(new boost::asio::io_service::work(bg_ios));
    boost::thread fg(boost::bind(&boost::asio::io_service::run, &fg_ios));
    boost::thread bg(boost::bind(&boost::asio::io_service::run, &bg_ios));
    
    aerospike::cluster cluster(fg_ios, bg_ios, 1);

    cluster.add_host(g_config.host, g_config.port);

    //wait for the cluster to pick up at least one node
    BOOST_LOG_TRIVIAL(info) << "waiting for cluster node(s)";
    cluster.wait_for_cluster();
    BOOST_LOG_TRIVIAL(info) << "found " << cluster.get_active_nodes().size() << " nodes";

    // Set up an array of event bases and thread IDs on the stack.
    base bases[DEFAULT_NUM_BASES];//g_config.num_bases];

    // Make these globally available.
    g_bases = bases;

    g_keys = new as_key[g_config.num_keys];

    for (int k = 0; k < DEFAULT_NUM_KEYS; k++)
        g_keys[k].assign(DEFAULT_NAMESPACE, DEFAULT_SET, k);
   
    for (int b = 0; b < g_config.num_bases; b++)
    {
        int key_per_shard = g_config.num_keys / g_config.num_bases;
        int key_begin = b*key_per_shard;
        int key_end = key_begin + key_per_shard;
        if (key_end <= g_config.num_keys)
        {
            put(&cluster, b, key_begin, key_begin, key_end);
            /*
                        bg_ios.post([&cluster, b, key_begin, key_end]() // get the background thread initialize callbacks 
            { 
                put(&cluster, b, key_begin, key_begin, key_end); 
            });
            */
        }
    }

    while (true)
    {
        boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
    }

    ev2citrusleaf_print_stats();
    //cl_partition_table_dump()

    //stop_cluster_management();

    BOOST_LOG_TRIVIAL(info) << "exiting";

    return 0;
}


//==========================================================
// Command Line Options
//

//------------------------------------------------
// Parse command line options.
//
static bool
set_config()
{
    g_config.host = DEFAULT_HOST;
    g_config.port = DEFAULT_PORT;
    g_config.ns = DEFAULT_NAMESPACE;
    g_config.set = DEFAULT_SET;
    g_config.trigger_usec = DEFAULT_TRIGGER_USEC;
    g_config.timeout_msec = DEFAULT_TIMEOUT_MSEC;
    g_config.num_bases = DEFAULT_NUM_BASES;
    g_config.num_keys = DEFAULT_NUM_KEYS;

    /*
        BOOST_LOG_TRIVIAL(info) << "host:               " << g_config.p_host;
        BOOST_LOG_TRIVIAL(info) << "port:               " << g_config.port;
        BOOST_LOG_TRIVIAL(info) << "namespace:          " << g_config.p_namespace;
        BOOST_LOG_TRIVIAL(info) << "set name:           " << g_config.p_set;
        BOOST_LOG_TRIVIAL(info) << "transaction trigger : every " << g_config.trigger_usec << " usec";
        BOOST_LOG_TRIVIAL(info) << "transaction timeout: %d msec", g_config.timeout_msec);
        BOOST_LOG_TRIVIAL(info) << "number of bases : %d", g_config.num_bases);
        BOOST_LOG_TRIVIAL(info) << "number of keys : %d", g_config.num_keys);
        */
    return true;
}

//------------------------------------------------
// Display supported command line options.
//
static void
usage()
{
    /*
    LOG("Usage:");
    LOG("-h host [default: %s]", DEFAULT_HOST);
    LOG("-p port [default: %d]", DEFAULT_PORT);
    LOG("-n namespace [default: %s]", DEFAULT_NAMESPACE);
    LOG("-s set name [default: %s]", DEFAULT_SET);
    LOG("-u transaction trigger usec [default: %d]", DEFAULT_TRIGGER_USEC);
    LOG("-m transaction timeout msec [default: %d]", DEFAULT_TIMEOUT_MSEC);
    LOG("-b number of bases [default: %d]", DEFAULT_NUM_BASES);
    LOG("-k number of keys [default: %d]", DEFAULT_NUM_KEYS);
    */
}


//------------------------------------------------
// Validate bin data read from database.
//
static void validate_data(int b, int k, const std::vector<std::shared_ptr<ev2citrusleaf_bin>>& bins)
{
    if (bins.size()==0) 
    {
        BOOST_LOG_TRIVIAL(error) << "base " << b << " key " << k << ", no bin data with return value OK";
        return;
    }

    if (bins.size() != 1)
    {
        BOOST_LOG_TRIVIAL(error) << "base " << b << " key " << k << " got unexpected n_bin " << bins.size();
    }
    else if (bins[0]->bin_name != BIN_NAME)
    {
        BOOST_LOG_TRIVIAL(error) << "base " << b << " key " << k << " got unexpected name " << bins[0]->bin_name;
    }
    else if (bins[0]->object.type != CL_INT) 
    {
        BOOST_LOG_TRIVIAL(error) << "base " << b << " key " << k << " got unexpected data type " << bins[0]->object.type;
    }
    else if (bins[0]->object.u.i64 != (int64_t)k) 
    {
        BOOST_LOG_TRIVIAL(error) << "base " << b << " key " << k << " got unexpected data value " << bins[0]->object.u.i64;
    }
}
