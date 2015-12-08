cmake_minimum_required(VERSION 2.8)
INCLUDE(${CMAKE_SOURCE_DIR}/CMakeDependencies.txt)

#SET(CPACK_DEB_COMPONENT_INSTALL 1)
#SET(USE_BUILTIN_CURL 1)
#SET(USE_BUILTIN_BOOST 1)


FILE(GLOB SRC1 aerospike_asio/*)
FILE(GLOB SRC2 citrusleaf/*)

add_library (aerospike-asio STATIC ${SRC1} ${SRC2})

if(WIN32)
include_directories(${LIBEVENTPATH}/compat)
add_definitions(-DHAVE_CONFIG_H)
#FILE(GLOB LIBEVENT_SOURCE1 ${LIBEVENTPATH}/*.c)
#FILE(GLOB LIBEVENT_SOURCE2 ${LIBEVENTPATH}/*.h)

SET (LIBEVENT_SOURCE1 
    ${LIBEVENTPATH}/event.c
    ${LIBEVENTPATH}/buffer.c
    ${LIBEVENTPATH}/bufferevent.c
    ${LIBEVENTPATH}/bufferevent_sock.c    
    ${LIBEVENTPATH}/bufferevent_pair.c        
    ${LIBEVENTPATH}/listener.c            
    ${LIBEVENTPATH}/evmap.c
    ${LIBEVENTPATH}/log.c    
    ${LIBEVENTPATH}/evutil.c        
    ${LIBEVENTPATH}/strlcpy.c
    ${LIBEVENTPATH}/signal.c    
    ${LIBEVENTPATH}/bufferevent_filter.c        
    ${LIBEVENTPATH}/evthread.c            
    ${LIBEVENTPATH}/bufferevent_ratelim.c                
    ${LIBEVENTPATH}/evutil_rand.c                    
    )
    
SET (LIBEVENT_WINSOURCE
    ${LIBEVENTPATH}/win32select.c
    ${LIBEVENTPATH}/evthread_win32.c
    ${LIBEVENTPATH}/buffer_iocp.c
    ${LIBEVENTPATH}/event_iocp.c    
    ${LIBEVENTPATH}/bufferevent_async.c        
    ${LIBEVENTPATH}/evutil_rand.c                    
    )

SET (LIBEVENT_EXTRA
    ${LIBEVENTPATH}/event_tagging.c
    ${LIBEVENTPATH}/http.c
    ${LIBEVENTPATH}/evdns.c
    ${LIBEVENTPATH}/evrpc.c    
    )

add_library (aerospike-asio-libevent STATIC ${LIBEVENT_SOURCE1} ${LIBEVENT_WINSOURCE} ${LIBEVENT_EXTRA})

set(EXT_LIBS aerospike-asio-libevent ${EXT_LIBS} Setupapi pthreadVC2)
endif() #WIN32

if(__LINUX__)
set(EXT_LIBS event ${EXT_LIBS})
endif()

#EXAMPLES

#include_directories(${CSI_HTTP_PATH})
#if(WIN32)
#link_directories(${CSI_HTTP_PATH}/lib/$(Platform))
#endif()

add_executable(example2 examples/example2.cpp)
target_link_libraries(example2 aerospike-asio ${EXT_LIBS})

add_executable(example_authenticate examples/example_authenticate.cpp)
target_link_libraries(example_authenticate aerospike-asio ${EXT_LIBS})
