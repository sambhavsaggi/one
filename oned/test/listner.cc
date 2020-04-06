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
        listener.start(1, [&](){
            if (state < 2)
            {
                ++state;
            }
        });
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

private:
    void _add(int a)
    {
        state += a;
    }

    int state;

    Listener listener;
};

TEST_CASE( "Listner and function callbacks", "[listener]" ) {
    EventAdder ea;

    std::thread t([&](){ea.start();});

    sleep(4); //Make sure at least 2 timers

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




