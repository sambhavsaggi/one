#define CATCH_CONFIG_MAIN
#include <iostream>
#include "catch.hpp"

#include "Message.h"

enum class DriverMessages
{
    UNDEFINED,
    INIT,
    FINALIZE,
    DEPLOY,
    RESUME,
    LOG,
    ENUM_MAX
};

template<>
const EString<DriverMessages> Message<DriverMessages>::_type_str({
    {"UNDEFINED", DriverMessages::UNDEFINED},
    {"INIT", DriverMessages::INIT},
    {"FINALIZE", DriverMessages::FINALIZE},
    {"DEPLOY", DriverMessages::DEPLOY},
    {"RESUME", DriverMessages::RESUME},
    {"LOG", DriverMessages::LOG}
});

TEST_CASE( "Enumerate string mapping", "[EnumString]" ) {

    Message<DriverMessages,false, false, false> none;

    std::string input="DEPLOY SUCCESS 34 one-34\n";

    int rc = none.parse_from(input);

    std::cout << rc << "\n";
    std::cout << none.type_str() << "\n";
    std::cout << none.payload() << "\n";
    std::cout << none.status() << "\n";
}

