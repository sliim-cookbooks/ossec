#
# Cookbook:: ossec
# Recipe:: repository
#
# Copyright:: 2015-2017, Chef Software, Inc.
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

case node['platform_family']
when 'fedora', 'rhel'
  include_recipe 'yum-atomic'
when 'debian'
  package ['lsb-release', 'apt-transport-https']

  ohai 'reload lsb' do
    plugin 'lsb'
    action :nothing
    subscribes :reload, 'package[lsb-release]', :immediately
  end

  distrib = node['platform_version'] == 'kali-rolling' ? 'stretch' : nil
  if node['ossec']['repo'] == 'wazuh'
    apt_repository 'wazuh' do
      uri 'https://packages.wazuh.com/apt'
      key 'https://packages.wazuh.com/key/GPG-KEY-WAZUH'
      distribution distrib || lazy { node['lsb']['codename'] }
      components ['main']
    end
  else
    apt_repository 'ossec' do
      uri 'https://ossec.wazuh.com/repos/apt/' + node['platform']
      key 'https://ossec.wazuh.com/repos/apt/conf/ossec-key.gpg.key'
      distribution distrib || lazy { node['lsb']['codename'] }
      components ['main']
    end
  end
end
