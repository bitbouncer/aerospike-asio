/*
 * Copyright 2012 Aerospike. All rights reserved.
 */
#pragma once

#include "cf_log.h"

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>

//====================================================================
// Internal API - for use by Aerospike client only
//

#ifndef CF_WINDOWS
//====================================================================
// Linux
//

#define cf_error(__fmt, __args...) \
	if (CF_ERROR <= G_LOG_LEVEL) {(*G_LOG_CB)(CF_ERROR, __fmt, ## __args);}

#define cf_warn(__fmt, __args...) \
	if (CF_WARN <= G_LOG_LEVEL) {(*G_LOG_CB)(CF_WARN, __fmt, ## __args);}

#define cf_info(__fmt, __args...) \
	if (CF_INFO <= G_LOG_LEVEL) {(*G_LOG_CB)(CF_INFO, __fmt, ## __args);}

#define cf_debug(__fmt, __args...) \
	if (CF_DEBUG <= G_LOG_LEVEL) {(*G_LOG_CB)(CF_DEBUG, __fmt, ## __args);}


#else // CF_WINDOWS
//====================================================================
// Windows
//

//#define cf_error(__fmt, ...) \
//	if (CF_ERROR <= G_LOG_LEVEL) {(*G_LOG_CB)(CF_ERROR, __fmt, ## __VA_ARGS__);}

//#define cf_warn(__fmt, ...) \
//	if (CF_WARN <= G_LOG_LEVEL) {(*G_LOG_CB)(CF_WARN, __fmt, ## __VA_ARGS__);}

//#define cf_info(__fmt, ...) \
//	if (CF_INFO <= G_LOG_LEVEL) {(*G_LOG_CB)(CF_INFO, __fmt, ## __VA_ARGS__);}

//#define cf_debug(__fmt, ...) \
//	if (CF_DEBUG <= G_LOG_LEVEL) {(*G_LOG_CB)(CF_DEBUG, __fmt, ## __VA_ARGS__);}

#if defined ( WIN32 )
#define __func__ __FUNCTION__
#endif
#endif // CF_WINDOWS

#define AEROSPIKE_DEBUG   BOOST_LOG_TRIVIAL(debug) << "aerospike::" << __func__ << " "
#define AEROSPIKE_INFO   BOOST_LOG_TRIVIAL(info) << "aerospike::" << __func__ << " "
#define AEROSPIKE_WARN   BOOST_LOG_TRIVIAL(warning) << "aerospike::" << __func__ << " "
#define AEROSPIKE_ERROR  BOOST_LOG_TRIVIAL(error) << "aerospike::" << __func__ << " "

