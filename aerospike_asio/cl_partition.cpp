/*
 * A good, basic C client for the Aerospike protocol
 * Creates a library which is linkable into a variety of systems
 *
 * The cl_partitions section creates a simple in-memory database of where
 * all the partitions in the system can be located.
 *
 * Brian Bulkowski, 2009
 * All rights reserved
 */

#include <stdlib.h>
#include <string.h>

#include "citrusleaf/cf_atomic.h"
#include "citrusleaf/cf_base_types.h"
#include "citrusleaf/cf_log_internal.h"

#include "cl_cluster.h"
#include "ev2citrusleaf.h"
#include "ev2citrusleaf-internal.h"



cl_partition_table::cl_partition_table(const char* ans, size_t nr_of_partitions) : 
_nr_of_partitions(nr_of_partitions),
was_dumped(false)
{
    strcpy(ns, ans);
    _partitions = new cl_partition[nr_of_partitions];
}

cl_partition_table::~cl_partition_table()
{
    delete[] _partitions;
}


bool cl_partition_table_is_node_present(cl_cluster_node* node)
{
	ev2citrusleaf_cluster* asc = node->asc;
	int n_partitions = (int)asc->n_partitions;
    for (std::vector<cl_partition_table*>::const_iterator i = asc->_partition_table_v.begin(); i != asc->_partition_table_v.end(); ++i)
    {
        for (int pid = 0; pid < n_partitions; pid++)
        {
            cl_partition* p = &(*i)->_partitions[pid];
            aerospike::spinlock::scoped_lock xxx(p->_spinlock);
            // Assuming a legitimate node must be master of some partitions,
            // this is all we need to check.
            if (node == p->master)
                return true;
        }
    }
	// The node is master of no partitions - it's effectively gone from the
	// cluster. The node shouldn't be present as prole, but it's possible it's
	// not completely overwritten as prole yet, so just remove it here.

    for (std::vector<cl_partition_table*>::const_iterator i = asc->_partition_table_v.begin(); i != asc->_partition_table_v.end(); ++i)
    {
		for (int pid = 0; pid < n_partitions; pid++) 
        {
			cl_partition* p = &(*i)->_partitions[pid];
            aerospike::spinlock::scoped_lock xxx(p->_spinlock);
			if (node == p->prole) 
            {
				cl_cluster_node_release(node, "PP-");
				p->prole = NULL;
				(*i)->was_dumped = false;
			}
    	}
	}
	return false;
}


static inline void
force_replicas_refresh(cl_cluster_node* node)
{
	cf_atomic_int_set(&node->partition_generation, (cf_atomic_int_t)-1);
}

void
cl_partition_table_update(cl_cluster_node* node, const char* ns, bool* masters, bool* proles)
{
	ev2citrusleaf_cluster* asc = node->asc;
	cl_partition_table* pt = asc->cl_partition_table_get_by_ns(ns);

	if (! pt) 
    {
		pt = asc->cl_partition_table_create(ns);

		if (! pt) 
        {
			return;
		}
	}

	int n_partitions = (int)asc->n_partitions;

	for (int pid = 0; pid < n_partitions; pid++) 
    {
		cl_partition* p = &pt->_partitions[pid];
        aerospike::spinlock::scoped_lock xxx(p->_spinlock);
		// Logic is simpler if we remove this node as master and prole first.
		// (Don't worry, these releases won't cause node destruction.)

		if (node == p->master) {
			cl_cluster_node_release(node, "PM-");
			p->master = NULL;
		}

		if (node == p->prole) {
			cl_cluster_node_release(node, "PP-");
			p->prole = NULL;
		}

		if (masters[pid]) {
			// This node is the new (or still) master for this partition.

			if (p->master) {
				// Replacing another master.
				force_replicas_refresh(p->master);
				cl_cluster_node_release(p->master, "PM-");
			}

			p->master = node;
			cl_cluster_node_reserve(node, "PM+");
		}
		else if (proles[pid]) {
			// This node is the new (or still) prole for this partition.

			if (p->prole) {
				// Replacing another prole.
				force_replicas_refresh(p->prole);
				cl_cluster_node_release(p->prole, "PP-");
			}

			p->prole = node;
			cl_cluster_node_reserve(node, "PP+");
		}
	}

	// Just assume something changed...
	pt->was_dumped = false;
}

