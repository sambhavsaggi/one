#!/bin/bash

# -------------------------------------------------------------------------- #
# Copyright 2002-2020, OpenNebula Project, OpenNebula Systems                #
#                                                                            #
# Licensed under the Apache License, Version 2.0 (the "License"); you may    #
# not use this file except in compliance with the License. You may obtain    #
# a copy of the License at                                                   #
#                                                                            #
# http://www.apache.org/licenses/LICENSE-2.0                                 #
#                                                                            #
# Unless required by applicable law or agreed to in writing, software        #
# distributed under the License is distributed on an "AS IS" BASIS,          #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   #
# See the License for the specific language governing permissions and        #
# limitations under the License.                                             #
#--------------------------------------------------------------------------- #

IO_FIFO_PATH="/tmp/vcenter_monitor.fifo"

#--------------------------------------------------------------------------- #
# Process Arguments
#--------------------------------------------------------------------------- #
ACTION="start"

if [ "$1" = "stop" ]; then
    shift
    ACTION="stop"
fi

ARGV=$*
HYPERV=$1
HID=$2

STDIN=`cat -`

MONITOR_ACTION="$ACTION $HID $STDIN"

#todo check it is running wait for fifo

echo $MONITOR_ACTION > $IO_FIFO_PATH

exit 0

