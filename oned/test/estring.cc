#define CATCH_CONFIG_MAIN
#include "EnumString.h"
#include <iostream>
#include "catch.hpp"

enum class DriverMessages : unsigned short int
{
    UNDEFINED    = 0,
    INIT         = 1,
    FINALIZE     = 2,
    DEPLOY       = 3,
    RESUME       = 4,
    LOG          = 5,
    ENUM_MAX
};

enum class VMState : unsigned short int
{
    UNDEFINED    = 0,
    INIT         = 1,
    ACTIVE       = 2,
    PENDING      = 3,
    STOPPED      = 40,
    DONE         = 44,
    ENUM_MAX
};

EString<DriverMessages> es_driver_messages({
    {"UNDEFINED", DriverMessages::UNDEFINED},
    {"INIT", DriverMessages::INIT},
    {"FINALIZE", DriverMessages::FINALIZE},
    {"DEPLOY", DriverMessages::DEPLOY},
    {"RESUME", DriverMessages::RESUME},
    {"LOG", DriverMessages::LOG}
});

EString<VMState> es_vmstate({
    {"UNDEFINED", VMState::UNDEFINED},
    {"INIT", VMState::INIT},
    {"ACTIVE", VMState::ACTIVE},
    {"PENDING", VMState::PENDING},
    {"STOPPED", VMState::STOPPED},
    {"DONE", VMState::DONE}
}, false);


TEST_CASE( "Enumerate string mapping", "[EnumString]" ) {
    std::string s1 = es_driver_messages._to_str(DriverMessages::DEPLOY);
    std::string s2 = es_vmstate._to_str(VMState::ACTIVE);

    REQUIRE( s1 == "DEPLOY" );
    REQUIRE( s2 == "ACTIVE" );

    VMState st1 = es_vmstate._from_str("PENDING");
    VMState st2 = es_vmstate._from_str("NONO_NANNA");

    REQUIRE( st1 == VMState::PENDING );
    REQUIRE( st2 == VMState::UNDEFINED );
}

