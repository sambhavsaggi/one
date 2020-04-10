/* -------------------------------------------------------------------------- */
/* Copyright 2002-2019, OpenNebula Project, OpenNebula Systems                */
/*                                                                            */
/* Licensed under the Apache License, Version 2.0 (the "License"); you may    */
/* not use this file except in compliance with the License. You may obtain    */
/* a copy of the License at                                                   */
/*                                                                            */
/* http://www.apache.org/licenses/LICENSE-2.0                                 */
/*                                                                            */
/* Unless required by applicable law or agreed to in writing, software        */
/* distributed under the License is distributed on an "AS IS" BASIS,          */
/* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   */
/* See the License for the specific language governing permissions and        */
/* limitations under the License.                                             */
/* -------------------------------------------------------------------------- */

#ifndef DRIVER_MESSAGE_H
#define DRIVER_MESSAGE_H

#include <unistd.h>

#include <string>
#include <iostream>
#include <sstream>

#include "EnumString.h"
#include "SSLUtil.h"

/**
 *  This class represents a generic message used by the Monitoring Protocol.
 *  The structure of the message is:
 *
 *  +------+-----+--------+-----+-----+---------+------+
 *  | TYPE | ' ' | STATUS | ' ' | OID | PAYLOAD | '\n' |
 *  +------+-----+--------+-----+-----+---------+------+
 *
 *    TYPE String (non-blanks) identifying the message type
 *    ' ' A single white space to separate fields
 *    STATUS String (non-blanks), status of the message depends on message
 *      type, could contain result of operation ("SUCCESS" or "FAILURE")
 *    OID Number, id of affected object, -1 if not object related
 *    PAYLOAD of the message XML base64 encoded
 *    '\n' End of message delimiter
 */
template<typename E, //Enum class for the message types
         bool T_encode   = false, //Payload is base64 encoded
         bool T_compress = false, //Payload is compressed
         bool T_encrypt  = false> //Payload is encrypted
class Message
{
public:
    /**
     *  Parse the Message from an input string
     *    @param input string with the message
     */
    int parse_from(const std::string& input);

    /**
     *  Writes this object to the given string
     */
    int write_to(std::string& out) const;

    /**
     *  Writes this object to the given file descriptor
     */
    int write_to(int fd) const;

    /**
     *  Writes this object to the given output stream
     */
    int write_to(std::ostream& oss) const;

    /**
     *
     */
    E type() const
    {
        return _type;
    }

    void type(E t)
    {
        _type = t;
    }

    /**
     *  Returns type of the message as string
     */
    const std::string& type_str() const
    {
        return _type_str._to_str(_type);
    }

    /**
     *  Status of the message, can't contain blanks.
     *  Depends on message type, could contain result of
     *  operation ("SUCCESS" or "FAILURE")
     *  Default value is "-"
     */
    const std::string& status() const
    {
        return _status;
    }

    void status(const std::string& status)
    {
        _status = status;
    }

    /**
     *  Object ID, -1 if not object related
     */
    int oid() const
    {
        return _oid;
    }

    void oid(int oid)
    {
        _oid = oid;
    }

    /**
     *  Message data, could be empty
     */
    const std::string& payload() const
    {
        return _payload;
    }

    void payload(const std::string& p)
    {
        _payload = p;
    }

private:
    /**
     *  Message fields
     */
    E _type;

    std::string _status = std::string("-");

    int _oid = -1;

    std::string _payload;

    static const EString<E> _type_str;

    /**
     *  Configuration flags for the message class
     */
     static constexpr const bool encode   = T_encode;

     static constexpr const bool compress = T_compress;

     static constexpr const bool encrypt  = T_encrypt;
};

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */
/* Message Template Implementation                                            */
/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

template<typename E, bool T_compress, bool T_encode, bool T_encrypt>
int Message<E, T_compress, T_encode, T_encrypt>::parse_from(const std::string& input)
{
    std::istringstream is(input);
    std::string buffer, payloaz;

    if (!is.good())
    {
        goto error;
    }

    is >> buffer;

    _type = _type_str._from_str(buffer.c_str());

    if ( !is.good() || _type == E::UNDEFINED )
    {
        goto error;
    }

    buffer.clear();

    is >> _status;

    is >> _oid;

    is >> buffer;

    if (buffer.empty())
    {
        _payload.clear();
        return 0;
    }

    if (encode)
    {
        ssl_util::base64_decode(buffer, payloaz);

        if ( compress && ssl_util::zlib_decompress(payloaz, _payload) == -1 )
        {
            goto error;
        }

        if ( encrypt && ssl_util::is_rsa_set() )
        {
            if ( ssl_util::rsa_private_decrypt(_payload, _payload) == -1 )
            {
                goto error;
            }
        }
    }
    else
    {
        _payload = buffer;
    }

    return 0;

error:
    _type    = E::UNDEFINED;
    _payload = input;
    return -1;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

template<typename E, bool T_compress, bool T_encode, bool T_encrypt>
int Message<E, T_compress, T_encode, T_encrypt>::write_to(std::string& out) const
{
    out.clear();

    out = _type_str._to_str(_type);
    out += ' ';
    out += _status.empty() ? "-" : _status;
    out += ' ';
    out += std::to_string(_oid);
    out += ' ';

    if (!_payload.empty())
    {
        if (encode)
        {
            std::string secret;
            std::string payloaz;
            std::string payloaz64;

            if (encrypt)
            {
                if (ssl_util::rsa_public_encrypt(_payload, secret) != 0)
                {
                    return -1;
                }
            }
            else
            {
                secret = _payload;
            }

            if (compress && ssl_util::zlib_compress(secret, payloaz) == -1)
            {
                return -1;
            }

            if ( ssl_util::base64_encode(payloaz, payloaz64) == -1)
            {
                return -1;
            }

            out += payloaz64;
        }
        else
        {
            out += _payload;
        }
    }

    out += '\n';

    return 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

template<typename E, bool T_compress, bool T_encode, bool T_encrypt>
int Message<E, T_compress, T_encode, T_encrypt>::write_to(int fd) const
{
    std::string out;

    if ( write_to(out) == -1)
    {
        return -1;
    }

    ::write(fd, (const void *) out.c_str(), out.size());

    return 0;
}

/* -------------------------------------------------------------------------- */
/* -------------------------------------------------------------------------- */

template<typename E, bool T_compress, bool T_encode, bool T_encrypt>
int Message<E, T_compress, T_encode, T_encrypt>::write_to(std::ostream& oss) const
{
    std::string out;

    if ( write_to(out) == -1)
    {
        return -1;
    }

    oss << out;

    return 0;
}

#endif /*DRIVER_MESSAGE_H_*/
