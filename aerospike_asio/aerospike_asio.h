#pragma once
#include <memory>
#include <boost/asio.hpp>
#include <boost/chrono/system_clocks.hpp>

#include "ev2citrusleaf.h"
#include "cl_cluster.h"

namespace aerospike
{
    struct put_request
    {
        put_request(as_key key_, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins_, ev2citrusleaf_write_parameters wparam_, int timeout_ms_) : key(key_), bins(bins_), wparam(wparam_), timeout_ms(timeout_ms_) {}
        as_key                                          key;
        std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins;
        ev2citrusleaf_write_parameters                  wparam;
        int                                             timeout_ms;
    };

    struct put_result
    {
        inline put_result(int ec_, uint32_t generation_, uint32_t expiration_) : ec(ec_), generation(generation_), expiration(expiration_) {}
        int ec;
        uint32_t generation;
        uint32_t expiration;
    };
    
    class cluster
    {
    public:
        typedef boost::function <void(std::vector<std::shared_ptr<put_result>>&)> mput_callback;


        cluster(boost::asio::io_service& fg_ios, boost::asio::io_service& ios, uint32_t polltime_ms = 15);
        ~cluster();

        void add_host(const std::string& host, uint16_t port);
        std::vector<std::string> get_active_nodes() const;
        void wait_for_cluster();

        //test
        void put(as_key, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, ev2citrusleaf_write_parameters wparam, int timeout_ms, ev2citrusleaf_put_callback cb);
        std::shared_ptr<put_result> put(as_key, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, ev2citrusleaf_write_parameters wparam, int timeout_ms);


        void mput(const std::vector<std::shared_ptr<put_request>>&, mput_callback);
        std::vector<std::shared_ptr<put_result>> mput(std::vector<std::shared_ptr<put_request>>);


        void get(as_key, std::vector<std::string> bins, int timeout_ms, ev2citrusleaf_get_callback cb);
        void get_all(as_key, int timeout_ms, ev2citrusleaf_get_callback cb);
        void delete_key(as_key key, ev2citrusleaf_write_parameters wparam, int timeout_ms, ev2citrusleaf_del_callback cb);
        void operate(as_key key, std::vector<ev2citrusleaf_operation> ops, ev2citrusleaf_write_parameters wparam, int timeout_ms, ev2citrusleaf_callback cb);


    private:

        int _bg_operate(const as_key& key, const std::vector<ev2citrusleaf_operation>& ops, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb);
        int _bg_delete_key(const as_key& key, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_del_callback cb);
        int _bg_get_all(const as_key&, int timeout_ms, ev2citrusleaf_get_callback cb);
        int _bg_get(const as_key&, const std::vector<std::string>& bins, int timeout_ms, ev2citrusleaf_get_callback cb);
        int _bg_put(const as_key&, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_put_callback cb);

        //MOVE DIGEST INTO KEY
        int _bg_get_all_digest(const std::string& ns, cf_digest *d, int timeout_ms, ev2citrusleaf_get_callback cb);
        int _bg_put_digest(const std::string& ns, cf_digest *d, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb);
        int _bg_get_digest(const std::string& ns, cf_digest* d, const std::vector<std::string>& bins, int timeout_ms, ev2citrusleaf_get_callback cb);
        int _bg_delete_digest(const std::string& ns, cf_digest* d, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb);
        int _bg_operate_digest(const std::string& ns, cf_digest* d, const std::vector<ev2citrusleaf_operation>& ops, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb);
        
        void inject_poll();
        bool run_event_loop();

        void keepalivetimer_cb(const boost::system::error_code & error);
        typedef boost::asio::basic_waitable_timer<boost::chrono::steady_clock> timer;
        boost::asio::io_service&	_bg_ios;
        boost::asio::io_service&	_fg_ios;
        uint32_t                    _polltime_ms;
        timer		                _pollevent_timer;
        bool                        _pending_post;
        ev2citrusleaf_cluster*      _cs_cluster;
        event_base*                 _event_base;
    };
};