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

ONE_LOCATION ||= ENV['ONE_LOCATION'] unless defined? ONE_LOCATION

if !ONE_LOCATION
    RUBY_LIB_LOCATION ||= '/usr/lib/one/ruby'
    GEMS_LOCATION     ||= '/usr/share/one/gems'
    ETC_LOCATION      ||= '/etc/one/'
    VAR_LOCATION      ||= '/var/lib/one/'
else
    RUBY_LIB_LOCATION ||= ONE_LOCATION + '/lib/ruby'
    GEMS_LOCATION     ||= ONE_LOCATION + '/share/gems'
    ETC_LOCATION      ||= ONE_LOCATION + '/etc/'
    VAR_LOCATION      ||= ONE_LOCATION + '/var/'
end

if File.directory?(GEMS_LOCATION)
    Gem.use_paths(GEMS_LOCATION)
    $LOAD_PATH.reject! {|l| l =~ /(vendor|site)_ruby/ }
end

$LOAD_PATH << RUBY_LIB_LOCATION

require 'opennebula'
require 'vcenter_driver'
require 'yaml'
require 'socket'
require 'base64'
require 'resolv'
require 'ipaddr'
require 'zlib'
require 'openssl'

require 'rexml/document'

require_relative '../lib/probe_db'


module VcenterMonitor
    CONFIGURATION = "#{VAR_LOCATION}/remotes/etc/vmm/vcenter/vcenterrc"

    #-------------------------------------------------------------------------------
    #  This class represents a monitord client. It handles udp and tcp connections
    #  and send update messages to monitord
    #-------------------------------------------------------------------------------
    class MonitorClient

        # Defined in src/monitor/include/MonitorDriverMessages.h
        MESSAGE_TYPES = %w[MONITOR_VM MONITOR_HOST SYSTEM_HOST BEACON_HOST STATE_VM
                           START_MONITOR STOP_MONITOR].freeze

        MESSAGE_STATUS = { true =>'SUCCESS', false => 'FAILURE' }.freeze

        MESSAGE_TYPES.each do |mt|
            define_method("#{mt}_udp".downcase.to_sym) do |rc, payload|
                msg = "#{mt} #{MESSAGE_STATUS[rc]} #{@hostid} #{pack(payload)}"
                @socket_udp.send(msg, 0)
            end
        end

        MESSAGE_TYPES.each do |mt|
            define_method("#{mt}_tcp".downcase.to_sym) do |rc, payload|
                msg = "#{mt} #{MESSAGE_STATUS[rc]} #{@hostid} #{pack(payload)}"

                socket_tcp = TCPSocket.new(@host, @port)
                socket_tcp.send(msg, 0)
                socket_tcp.close
            end
        end

        # Options to create a monitord client
        # :host [:String] to send the messages to
        # :port [:String] of monitord server
        # :hostid [:String] OpenNebula ID of this host
        # :pubkey [:String] public key to encrypt messages
        def initialize(server, port, id, opt = {})
            @opts = {
                :pubkey => ''
            }.merge opt

            addr = Socket.getaddrinfo(server, port)[0]

            @family = addr[0]
            @host   = addr[3]
            @port   = addr[1]

            @socket_udp = UDPSocket.new(@family)
            @socket_udp.connect(@host, @port)

            @pubkey = @opts[:pubkey]

            @hostid = id
        end

        private

        # Formats message payload to send over the wire
        def pack(data)
            if @pubkey
                block_size = @pubkey.n.num_bytes - 11

                edata = ''
                index = 0

                loop do
                    break if index >= data.length

                    edata << @pubkey.public_encrypt(data[index, block_size])

                    index += block_size
                end

                data = edata
            end

            zdata  = Zlib::Deflate.deflate(data, Zlib::BEST_COMPRESSION)
            data64 = Base64.strict_encode64(zdata)

            data64
        end

    end

    #---------------------------------------------------------------------------
    #
    #
    #---------------------------------------------------------------------------
    class VcenterHash
        def initialize
            @mutex  = Mutex.new
            @client = OpenNebula::Client.new

            @vcenters = {}
        end

        # Add a new vcenter (if needed)
        #   @param hid the host id
        #   @param hone Host (un-encrypted parameters)
        #   @param vcenter_id
        def add_vcenter(hid, hone, vcenter_id)
            @mutex.synchronize {
                return unless @vcenters[vcenter_id].nil?
            }

            if hone.nil?
                hone = OpenNebula::Host.new_with_id(hid, @client)
                hone.info(true)
            end

            vuser = hone["TEMPLATE/VCENTER_USER"]
            vpass = hone["TEMPLATE/VCENTER_PASSWORD"]
            vport = hone["TEMPLATE/VCENTER_PORT"]
            vhost = hone["TEMPLATE/VCENTER_HOST"]

            return if vuser.nil? || vpass.nil? || vport.nil? || vhost.nil?

            @mutex.synchronize {
                @vcenters[vcenter_id] = {
                      :id    => vcenter_id,
                      :vuser => vuser,
                      :vpass => vpass,
                      :vhost => vhost,
                      :vport => vport,
                      :hosts => []
                }
            }
        end

        # Add a host
        def add_host(id)
            hone = OpenNebula::Host.new_with_id(id, @client)
            hone.info(true)

            vcenter_id = hone["TEMPLATE/VCENTER_INSTANCE_ID"]

            return if vcenter_id.nil?

            add_vcenter(id, hone, vcenter_id)

            @mutex.synchronize {
                @vcenters[vcenter_id][:hosts] << hone unless @vcenters[vcenter_id].nil?
            }
        end

        # Del a host
        def del_host(id)
            hone = OpenNebula::Host.new_with_id(id, @client)
            hone.info(true)

            vcenter_id = hone["TEMPLATE/VCENTER_INSTANCE_ID"]

            @mutex.synchronize {
                return if vcenter_id.nil? || @vcenters[vcenter_id].nil?

                @vcenters[vcenter_id][:hosts].delete_if {|h| h.id.to_i == id.to_i}
            }
        end

        # One-time initialization of host pool
        def bootstrap
            hpool = OpenNebula::HostPool.new(@client)
            rc    = hpool.info

            if OpenNebula.is_error?(rc)
                raise "Could not get hosts information - #{rc.message}"
            end

            hpool.each do |hone|
                vcenter_id = hone["TEMPLATE/VCENTER_INSTANCE_ID"]

                next if vcenter_id.nil?

                add_vcenter(hone["ID"], nil, vcenter_id)

                @mutex.synchronize {
                    @vcenters[vcenter_id][:hosts] << hone unless @vcenters[vcenter_id].nil?
                }
            end
        end

        def to_s
            @vcenters.to_s
        end
    end

    #---------------------------------------------------------------------------
    #
    #
    #---------------------------------------------------------------------------
    class VcenterMonitorManager
        def initialize
            @vcenters = VcenterHash.new

            @vcenters.bootstrap

            # Create timer thread to monitor vcenters
            Thread.new {
                timer
            }
        end

        def start(hid, conf)
            @vcenters.add_host(hid)
        end

        def stop(hid, conf)
            @vcenters.del_host(hid)
        end

        def timer
            loop do
                sleep 10
                # Monitor vcenters and send monitor messages
                puts @vcenters.to_s
            end
        end

    end

    #---------------------------------------------------------------------------
    # This class receives inputs reading on the fifo, sends monitor messages
    # to monitord client and trigger operations on the Vcenter logic thread
    # --------------------------------------------------------------------------
    class IOThread
        IO_FIFO = "/tmp/vcenter_monitor.fifo"

        def initialize(vcentermm)
            @vcentermm = vcentermm

            if File.exist?(IO_FIFO)
                if File.ftype(IO_FIFO) != 'fifo'
                    File.unlink(IO_FIFO)
                    File.mkfifo(IO_FIFO)
                end
            else
                File.mkfifo(IO_FIFO)
            end
        end

        def command_loop
            loop do
                fifo = File.open(IO_FIFO)

                fifo.each_line { |line|
                    puts line
                    action, hid, conf = line.split

                    @vcentermm.send(action.to_sym, hid, conf)
                }
            end
        end
    end
end

vcentermm = VcenterMonitor::VcenterMonitorManager.new

io = VcenterMonitor::IOThread.new(vcentermm)

io.command_loop
