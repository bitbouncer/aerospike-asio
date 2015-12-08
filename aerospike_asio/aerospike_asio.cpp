#include <future>
#include <boost/bind.hpp>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/thread.hpp>
#include "aerospike_asio.h"
#include "async.h"

namespace aerospike
{
        cluster::cluster(boost::asio::io_service& fg_ios, boost::asio::io_service& bg_ios, uint32_t polltime_ms):
        _fg_ios(fg_ios),
        _bg_ios(bg_ios),
        _polltime_ms(polltime_ms),
        _pollevent_timer(bg_ios),
        _cs_cluster(NULL),
        _event_base(NULL),
        _pending_post(false)
    {
        _event_base = event_base_new();
        _cs_cluster = ev2citrusleaf_cluster::ev2citrusleaf_cluster_create(_event_base);

        if (!_cs_cluster)
        {
            BOOST_LOG_TRIVIAL(error) << "can't create cluster";
            //throw
        }
        
        _pollevent_timer.expires_from_now(boost::chrono::milliseconds(_polltime_ms));
        _pollevent_timer.async_wait(boost::bind(&cluster::keepalivetimer_cb, this, _1));
    }

    cluster::~cluster()
    {
        _pollevent_timer.cancel();
        event_base_free(_event_base);
        ev2citrusleaf_cluster::ev2citrusleaf_cluster_destroy(_cs_cluster);
    }

    void cluster::wait_for_cluster()
    {
        while (true)
        {
            boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
            auto nodes = get_active_nodes();
            if (nodes.size())
                break;
        }
    }

    bool cluster::run_event_loop()
    {
        _pending_post = false; // bad name
        //0 ok
        //-1 ERROR
        //-2 no events where pending or active
        return (event_base_loop(_event_base, EVLOOP_NONBLOCK) == 0);
    }

    void cluster::inject_poll()
    {
        if (!_pending_post)
        {
            _bg_ios.post([this](){run_event_loop(); });
            _pending_post = true;
        }
    }

    void cluster::keepalivetimer_cb(const boost::system::error_code & error)
    {
        if (!error)
        {
            run_event_loop();
            _pollevent_timer.expires_from_now(boost::chrono::milliseconds(_polltime_ms));
            _pollevent_timer.async_wait(boost::bind(&cluster::keepalivetimer_cb, this, _1));
        }
    }


    void cluster::add_host(const std::string& host, uint16_t port)
    {
        _cs_cluster->ev2citrusleaf_cluster_add_host(host.c_str(), port);
    }

    std::vector<std::string> cluster::get_active_nodes() const
    {
        return _cs_cluster->get_nodes_names();
    }
    
    void cluster::put(as_key key, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, ev2citrusleaf_write_parameters wparam, int timeout_ms, ev2citrusleaf_put_callback cb)
    {
        _bg_ios.post([this, key, bins, wparam, timeout_ms, cb]()
        {
            _bg_put(key, bins, &wparam, timeout_ms, [this, cb](int ec, uint32_t generation, uint32_t expiration)
            {
                _fg_ios.post([this, cb, ec, generation, expiration]() { cb(ec, generation, expiration); });
            });
        });
    }

    std::shared_ptr<put_result> cluster::put(as_key key, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, ev2citrusleaf_write_parameters wparam, int timeout_ms)
    {
        std::promise<std::shared_ptr<put_result>> p;
        std::future<std::shared_ptr<put_result>>  f = p.get_future();
        put(key, bins, wparam, timeout_ms, [&p](int ec, uint32_t generation, uint32_t expiration)
        {
            p.set_value(std::make_shared<put_result>(ec, generation, expiration));
        });
        f.wait();
        return f.get();
    }

    void cluster::mput(const std::vector<std::shared_ptr<put_request>>& req, mput_callback cb)
    {
        auto final_cb = std::make_shared<aerospike::async::destructor_callback<std::vector<std::shared_ptr<put_result>>>>(cb);
        size_t sz = req.size();
        final_cb->value().resize(sz);

        for (int i = 0; i != sz; ++i)
        {
            put(req[i]->key, req[i]->bins, req[i]->wparam, req[i]->timeout_ms, [final_cb, i](int ec, uint32_t generation, uint32_t expiration)
            {
                final_cb->value()[i] = std::make_shared<put_result>(ec, generation, expiration);
            });
        }
    }

    std::vector<std::shared_ptr<put_result>> cluster::mput(std::vector<std::shared_ptr<put_request>> req)
    {
        std::promise<std::vector<std::shared_ptr<put_result>> > p;
        std::future<std::vector<std::shared_ptr<put_result>> >  f = p.get_future();
        mput(req, [&p](std::vector<std::shared_ptr<put_result>>& res)
        {
            p.set_value(res);
        });
        f.wait();
        return f.get();
    }

    int cluster::_bg_put(const as_key& key, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_put_callback cb)
    {
        inject_poll();

        // a status here should really go into a callback otherwise it's lost from fg. TBD
        return _cs_cluster->ev2citrusleaf_put(_event_base, key, bins, wparam, timeout_ms, [cb](int ec, std::vector<std::shared_ptr<ev2citrusleaf_bin>>, uint32_t generation, uint32_t expiration)
        {
            cb(ec, generation, expiration);
        });
    }

    void cluster::get(as_key key, std::vector<std::string> bins, int timeout_ms, ev2citrusleaf_get_callback cb)
    {
        _bg_ios.post([this, key, bins, timeout_ms, cb]()
        {
            _bg_get(key, bins, timeout_ms, [this, cb](int ec, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, uint32_t generation, uint32_t expiration)
            {
                _fg_ios.post([this, cb, ec, bins, generation, expiration]() { cb(ec, bins, generation, expiration); });
            });
        });
    }

    int cluster::_bg_get(const as_key& key, const std::vector<std::string>& bins, int timeout_ms, ev2citrusleaf_get_callback cb)
    {
        inject_poll();
        return _cs_cluster->ev2citrusleaf_get(_event_base, key, bins, timeout_ms, cb);
    }

    void cluster::get_all(as_key key, int timeout_ms, ev2citrusleaf_get_callback cb)
    {
        _bg_ios.post([this, key, timeout_ms, cb]()
        {
            _bg_get_all(key, timeout_ms, [this, cb](int ec, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, uint32_t generation, uint32_t expiration)
            {
                _fg_ios.post([this, cb, ec, bins, generation, expiration]() { cb(ec, bins, generation, expiration); });
            });
        });
    }

    int cluster::_bg_get_all(const as_key& key, int timeout_ms, ev2citrusleaf_get_callback cb)
    {
        inject_poll();
        return _cs_cluster->ev2citrusleaf_get_all(_event_base, key, timeout_ms, cb);
    }

    void cluster::delete_key(as_key key, ev2citrusleaf_write_parameters wparam, int timeout_ms, ev2citrusleaf_del_callback cb)
    {
        _bg_ios.post([this, key, wparam, timeout_ms, cb]()
        {
            _bg_delete_key(key, &wparam, timeout_ms, [this, cb](int ec, uint32_t generation, uint32_t expiration)
            {
                _fg_ios.post([this, cb, ec, generation, expiration]() { cb(ec, generation, expiration); });
            });
        });
    }


    int cluster::_bg_delete_key(const as_key& key, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_del_callback cb)
    {
        inject_poll();
        // a status here should really go into a callback otherwise it's lost from fg. TBD
        return _cs_cluster->ev2citrusleaf_delete(_event_base, key, wparam, timeout_ms, [cb](int ec, std::vector<std::shared_ptr<ev2citrusleaf_bin>>, uint32_t generation, uint32_t expiration)
        {
            cb(ec, generation, expiration);
        });
    }

    void cluster::operate(as_key key, std::vector<ev2citrusleaf_operation> ops, ev2citrusleaf_write_parameters wparam, int timeout_ms, ev2citrusleaf_callback cb)
    {
        _bg_ios.post([this, key, ops, wparam, timeout_ms, cb]()
        {
            _bg_operate(key, ops, &wparam, timeout_ms, [this, cb](int ec, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, uint32_t generation, uint32_t expiration)
            {
                _fg_ios.post([this, cb, ec, bins, generation, expiration]() { cb(ec, bins, generation, expiration); });
            });
        });
    }


    int cluster::_bg_operate(const as_key& key, const std::vector<ev2citrusleaf_operation>& ops, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb)
    {
        inject_poll();
        return _cs_cluster->ev2citrusleaf_operate(_event_base, key, ops, wparam, timeout_ms, cb);
    }
  
    int cluster::_bg_get_all_digest(const std::string& ns, cf_digest *d, int timeout_ms, ev2citrusleaf_get_callback cb)
    {
        inject_poll();
        return _cs_cluster->ev2citrusleaf_get_all_digest(_event_base, ns.c_str(), d, timeout_ms, cb);
    }

    int cluster::_bg_put_digest(const std::string& ns, cf_digest *d, std::vector<std::shared_ptr<ev2citrusleaf_bin>> bins, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb)
    {
        inject_poll();
        return _cs_cluster->ev2citrusleaf_put_digest(_event_base, ns.c_str(), d, bins, wparam, timeout_ms, cb);
    }

    int cluster::_bg_get_digest(const std::string& ns, cf_digest* d, const std::vector<std::string>& bins, int timeout_ms, ev2citrusleaf_get_callback cb)
    {
        inject_poll();
        return _cs_cluster->ev2citrusleaf_get_digest(_event_base, ns.c_str(), d, bins, timeout_ms, cb);
    }
    

    int cluster::_bg_delete_digest(const std::string& ns, cf_digest* d, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb)
    {
        inject_poll();
        return _cs_cluster->ev2citrusleaf_delete_digest(_event_base, ns.c_str(), d, wparam, timeout_ms, cb);
    }

   
    int cluster::_bg_operate_digest(const std::string& ns, cf_digest* d, const std::vector<ev2citrusleaf_operation>& ops, const ev2citrusleaf_write_parameters *wparam, int timeout_ms, ev2citrusleaf_callback cb)
    {
        inject_poll();
        return _cs_cluster->ev2citrusleaf_operate_digest(_event_base, ns.c_str(), d, ops, wparam, timeout_ms, cb);
    }
};
