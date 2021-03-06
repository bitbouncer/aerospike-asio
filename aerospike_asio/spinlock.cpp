//
// spinlock.cpp
// ~~~~~~~~~
// Copyright 2014 Svante Karlsson CSI AB (svante.karlsson at csi dot se)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "spinlock.h"

namespace aerospike
{
    static boost::detail::spinlock initializer = BOOST_DETAIL_SPINLOCK_INIT;
    spinlock::spinlock() : _sl(initializer) {}
}; // namespace
