#define CATCH_CONFIG_MAIN
#include "Listener.h"
#include <thread>
#include <unistd.h>
#include "catch.hpp"

class EventAdder
{
public:
    void start()
    {
        timer.reset(new Timer(1, [&]{ timer_action(); }));

        listener.start();
    }

    void finalize()
    {
        listener.finalize();
    }

    EventAdder():state(0){};

    void add(int a)
    {
        auto fn = std::bind(&EventAdder::_add, this, a);

        listener.trigger(fn);
    }

    int adder()
    {
        return state;
    }

    void timer_action()
    {
        if ( state < 2 )
        {
            ++state;
        }
    }

private:
    void _add(int a)
    {
        state += a;
    }

    int state;

    Listener listener;

    std::unique_ptr<Timer> timer;
};

TEST_CASE( "Listner and function callbacks", "[listener]" ) {
    EventAdder ea;

    std::thread t([&](){ea.start();});

    sleep(4); //Make sure at least 2 timers

    REQUIRE( ea.adder() == 2 );

    ea.add(2);

    sleep(1);

    REQUIRE( ea.adder() == 4 );

    ea.add(2);

    sleep(1);

    REQUIRE( ea.adder() == 6 );

    ea.finalize();

    t.join();

    REQUIRE( ea.adder() == 6 );
}




