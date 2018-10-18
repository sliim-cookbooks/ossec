#
# Cookbook:: ossec
# Recipe:: common
#
# Copyright:: 2010-2017, Chef Software, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

ruby_block 'ossec install_type' do # ~FC014
  block do
    if node.recipe?('ossec::default')
      type = 'local'
    elsif node.recipe?('ossec::server')
      type = 'server'
    elsif node.recipe?('ossec::client') || node.recipe?('ossec::agent')
      type = 'agent'
    else
      type = nil

      File.open('/etc/ossec-init.conf') do |file|
        file.each_line do |line|
          if line =~ /^TYPE="([^"]+)"/
            type = Regexp.last_match(1)
            break
          end
        end
      end
    end

    node.normal['ossec']['install_type'] = type
  end
end

# Gyoku renders the XML.
chef_gem 'gyoku' do
  compile_time false
end

file "#{node['ossec']['dir']}/etc/ossec.conf" do
  owner 'root'
  group 'ossec'
  mode '0440'
  manage_symlink_source true
  notifies :restart, 'service[ossec]'

  content lazy {
    # Merge the "typed" attributes over the "all" attributes.
    all_conf = node['ossec']['conf']['all'].to_hash
    type_conf = node['ossec']['conf'][node['ossec']['install_type']].to_hash
    conf = Chef::Mixin::DeepMerge.deep_merge(type_conf, all_conf)
    Chef::OSSEC::Helpers.ossec_to_xml('ossec_config' => conf)
  }
end

rules_dir = if node['ossec']['install_type'] == 'local'
              "#{node['ossec']['dir']}/rules"
            else
              "#{node['ossec']['dir']}/etc/rules"
            end

directory rules_dir do
  action :create
  owner 'root'
  owner 'ossec'
  mode '0550'
end

file "#{rules_dir}/local_rules.xml" do
  action :create
  owner 'root'
  owner 'ossec'
  mode '0440'
  notifies :restart, 'service[ossec]', :delayed
  content Chef::OSSEC::Helpers.ossec_to_xml(node['ossec']['local_rules'].to_hash)
  only_if { node['ossec']['local_rules'] }
end

file "#{node['ossec']['dir']}/etc/shared/agent.conf" do
  owner 'root'
  group 'ossec'
  mode '0440'
  notifies :restart, 'service[ossec]'

  # Even if agent.cont is not appropriate for this kind of
  # installation, we need to create an empty file instead of deleting
  # for two reasons. Firstly, install_type is set at converge time
  # while action can't be lazy. Secondly, a subsequent package update
  # would just replace the file.
  action :create

  content lazy {
    if node['ossec']['install_type'] == 'server'
      conf = node['ossec']['agent_conf'].to_a
      Chef::OSSEC::Helpers.ossec_to_xml('agent_config' => conf)
    else
      ''
    end
  }
end

file "#{node['ossec']['dir']}/etc/decoders/local_decoder.xml" do
  action :create
  owner 'root'
  owner 'ossec'
  mode '0440'
  notifies :restart, 'service[ossec]', :delayed
  content Chef::OSSEC::Helpers.ossec_to_xml(node['ossec']['local_decoders'].to_hash)
  not_if { node['ossec']['local_decoders'].empty? }
end

if node['ossec']['repo'] == 'wazuh'
  sname = node.recipe?('ossec::server') || node.recipe?('ossec::default') ? 'wazuh-manager' : 'wazuh-agent'
else
  sname = platform_family?('debian') ? 'ossec' : 'ossec-hids'

# Both the RPM and DEB packages enable and start the service
# immediately after installation, which isn't helpful. An empty
# client.keys file will cause a server not to listen and an agent to
# abort immediately. Explicitly stopping the service here after
# installation allows Chef to start it when client.keys has content.
service 'stop ossec' do # ~FC037
  service_name sname
  action :nothing

  %w( disable stop ).each do |action|
    subscribes action, "package[#{sname}]", :immediately
  end
end

service 'ossec' do
  service_name sname
  supports status: true, restart: true, enable: true
  action [:enable, :start]

  not_if do
    (node['ossec']['install_type'] != 'local' && !File.size?("#{node['ossec']['dir']}/etc/client.keys")) ||
      (node['ossec']['install_type'] == 'agent' && node['ossec']['agent_server_ip'].nil?)
  end
end
