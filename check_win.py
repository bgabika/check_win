#!/usr/bin/python3
# -*- coding: utf-8 -*-
# ---------------------------------------------------------------
# COREX Windows host agentless check plugin for Icinga 2
# Copyright (C) 2019-2025, Gabor Borsos <bg@corex.bg>
# 
# v1.18 built on 2025.03.30.
# usage: check_win.py --help
#
# For bugs and feature requests mailto bg@corex.bg
# 
# ---------------------------------------------------------------
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# Test it in test environment to stay safe and sensible before 
# using in production!
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# ---------------------------------------------------------------

import io
import sys

try:
    from enum import Enum
    import argparse
    import json
    import paramiko
    import re
    import textwrap

except ImportError as e:
    print("Missing python module: {}".format(str(e)))
    sys.exit(255)


class CheckState(Enum):
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3


class CheckWin:

    def __init__(self):

        self.result_list = []
        self.pluginname = "check_win.py"
        self.parse_args()



    def parse_args(self):
        parser = argparse.ArgumentParser(
            prog=self.pluginname, 
            add_help=True, 
            formatter_class=argparse.RawTextHelpFormatter,
            description = textwrap.dedent("""
            PLUGIN DESCRIPTION: COREX Windows host agentless check plugin for Icinga 2.
            This plugin works under Windows 10 up to 2019 Server."""),
            epilog = textwrap.dedent(f"""
            Examples:
            {self.pluginname} --hostname myserver.mydomain.com --sshuser john.doe --sshkey mykey --subcommand disk-usage --ignore-drive E --warning 70 --critical 90
            {self.pluginname} --hostname myserver.mydomain.com --sshuser john.doe --sshkey mykey --subcommand disk-health
            {self.pluginname} --hostname myserver.mydomain.com --sshuser john.doe --sshkey mykey --subcommand network --warning 70 --critical 90
            {self.pluginname} --hostname myserver.mydomain.com --sshuser john.doe --sshkey mykey --subcommand cpu --warning 70 --critical 90"""))
        
        api_connect_opt = parser.add_argument_group('SSH connection arguments', 'hostname, sshuser, sshport, sshkey')

        api_connect_opt.add_argument('--hostname', dest="hostname", type=str, required=True, help="host FQDN or IP")
        api_connect_opt.add_argument('--sshport', type=int, required=False, help="ssh port, default port: 22", default=22)
        api_connect_opt.add_argument('--sshuser', type=str, required=True, help="ssh user")
        api_connect_opt.add_argument('--sshkey', type=str, required=True, help="ssh key file")


        check_win_opt = parser.add_argument_group('check arguments', 'cpu, disk-health, disk-io, disk-usage, memory, network, procs, swap, user-logged-on, user-count, winfo')
        
        check_win_opt.add_argument("--subcommand",
                                        choices=(
                                            'cpu', 'disk-health', 'disk-io','disk-usage', 'memory', 'network', 'procs', 'swap', 'user-logged-on', 'user-count', 'winfo'),
                                        required=True,
                                        help="Select subcommand to use. Some subcommands need warning and critical arguments.")
                                            
        
        check_win_opt.add_argument('--ignore-drive', dest='ignore_drive', action='append', metavar='DRIVE-LETTER',
                                        help='Ignore drive in disk-usage check, --ignore-drive C --ignore-drive E ...etc', default=[])

        check_win_opt.add_argument('--drive-letter', dest='include_drive', action='append', metavar='DRIVE-LETTER',
                                        help='Check drive in disk-usage check by drive letter, --drive-letter C --drive-letter E ...etc', default=[])
        
        check_win_opt.add_argument('--ignore-username', dest='ignore_usernames', action='append', metavar='IGNORE-USERNAME',
                                        help='Ignore username in user-count check, --ignore-username john.doe --ignore-username jane.doe ...etc', default=[])

        check_win_opt.add_argument('--warning', dest='threshold_warning', type=int,
                                        help='Warning threshold for check value. Some subcommand needs warning threshold.')
        
        check_win_opt.add_argument('--critical', dest='threshold_critical', type=int,
                                        help='Critical threshold for check value. Some subcommand needs critical threshold.')

        self.options = parser.parse_args()

        # check args dependencies
        if (self.options.subcommand == "cpu" or self.options.subcommand == "disk-io" or self.options.subcommand == "disk-usage" or self.options.subcommand == "memory" \
            or self.options.subcommand == "network" or self.options.subcommand == "procs" or self.options.subcommand == "services" \
            or self.options.subcommand == "swap") and (self.options.threshold_warning is None or self.options.threshold_critical is None):
            
            parser.error(f"--warning and --critical arguments are required for '{self.options.subcommand}' subcommand!")
            
        # check thresholds scale
        if self.check_thresholds_scale("increase") == False:
            parser.error(f"--warning threshold must be lower then --critical threshold for '{self.options.subcommand}' subcommand!")
        elif self.check_thresholds_scale("decrease") == False:
            parser.error(f"--warning threshold must be higher then --critical threshold for '{self.options.subcommand}' subcommand!")



    def main(self):
        
        perfdata = self.get_perfdata(self.options.hostname, self.options.sshport, self.options.sshuser, self.options.sshkey)
        
        # run function by variable name, call function by varible name
        subcommand_function = (self.options.subcommand).replace("-", "_")
        self.result_list = eval(f"self.check_{subcommand_function}" + "(perfdata, self.options.subcommand)")
        self.check_exitcodes(self.result_list)
    


    @staticmethod
    def output(state, message):
        prefix = state.name
        message = '{} - {}'.format(prefix, message)
        print(message)
        sys.exit(state.value)



    @staticmethod
    def check_UOM(mynumber):
        mynumber_lenght = len(str(mynumber))
        my_unit = "GB"
        if mynumber_lenght >= 13:
            mynumber = round(mynumber/1024**4, 2)
            my_unit = "TB"
            
        if mynumber_lenght >= 10 and mynumber_lenght <= 12:
            mynumber = round(mynumber/1024**3, 2)
            my_unit = "GB"

        if mynumber_lenght < 10:
            mynumber = round(mynumber/1024**2, 2)
            my_unit = "MB"

        return mynumber, my_unit



    def get_perfdata(self, hostname, sshport, sshuser, sshkey):
        if self.options.subcommand == "cpu":
            wincommand = """powershell "Get-CimInstance -ClassName win32_processor | Measure-Object -Property LoadPercentage -Average | Select Average | ft -HideTableHeaders -autosize\""""

        elif self.options.subcommand == "disk-health":
            wincommand = """powershell "Get-PhysicalDisk | select DeviceId, Model, MediaType, OperationalStatus, HealthStatus, Size\""""

        elif self.options.subcommand == "disk-io":
            wincommand = """powershell "Get-WMIObject -Class \"Win32_PerfFormattedData_PerfDisk_PhysicalDisk\" -Filter 'Name = \\"_Total\\"' | Select-Object Name, PercentDiskTime | ft -HideTableHeaders -autosize; Get-WmiObject Win32_PerfFormattedData_PerfProc_Process | Where-Object{ $_.IODataOperationsPersec } | Select-Object Name, IODataOperationsPersec | ft -HideTableHeaders -autosize\""""

        elif self.options.subcommand == "disk-usage":
            wincommand = """powershell "Get-Volume | select DriveLetter, SizeRemaining, Size, FileSystemLabel | ft -HideTableHeaders -autosize\""""
        
        elif self.options.subcommand == "memory":
            wincommand = """powershell "$CompObject = Get-WmiObject -Class WIN32_OperatingSystem; $CompObject.FreePhysicalMemory; $CompObject.TotalVisibleMemorySize\""""
        
        elif self.options.subcommand == "network":
            # wincommand = """powershell -Command "(Get-CimInstance -Query 'Select Name, BytesReceivedPersec, BytesSentPersec from Win32_PerfFormattedData_Tcpip_NetworkInterface' | Select-Object Name, BytesReceivedPersec, BytesSentPersec | ConvertTo-Json) ; (Get-CimInstance win32_networkadapterconfiguration | where {$_.IPAddress -ne $null} | Select-Object Description, MACAddress, IPAddress | ConvertTo-Json)\""""
            wincommand = (
    "powershell -Command "
    "\""
    "$perfData = Get-CimInstance -Query 'Select Name, BytesReceivedPersec, BytesSentPersec from Win32_PerfFormattedData_Tcpip_NetworkInterface' | "
    "    Select-Object Name, BytesReceivedPersec, BytesSentPersec; "

    "$networkConfig = Get-CimInstance win32_networkadapterconfiguration | "
    "    Where-Object { $_.IPAddress -ne $null } | "
    "    Select-Object Description, MACAddress, IPAddress; "

    "if ($perfData -or $networkConfig) { "
    "    $allData = @(); "
    "    if ($perfData) { $allData += $perfData }; "
    "    if ($networkConfig) { $allData += $networkConfig }; "
    "    $allData | ConvertTo-Json -Depth 3 -Compress; "
    "}"
    "\""
)



        elif self.options.subcommand == "procs":
            wincommand = """powershell "(Get-Process).count\""""
        
        elif self.options.subcommand == "swap":
            wincommand = """powershell "$colItems = get-wmiobject -class "Win32_PageFileUsage" -namespace "root\CIMV2" -computername localhost; foreach ($objItem in $colItems) { $allocate = $objItem.AllocatedBaseSize; $current = $objItem.CurrentUsage} ;write-host ($allocate-$current), `r`n$allocate\""""

        elif self.options.subcommand == "user-logged-on":
            wincommand = """powershell "query user /server:$server\""""

        elif self.options.subcommand == "user-count":
            wincommand = """powershell "Get-LocalUser | Where-Object -Property Enabled -eq True | Select Name | ft -HideTableHeaders -autosize\""""

        elif self.options.subcommand == "winfo":
            wincommand = """powershell "Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property CSName, Caption, Version, InstallDate, LastBootupTime\""""

        perfdata = self.run_ssh_command(wincommand, hostname, sshport, sshuser, sshkey)
        # print(f"raw {perfdata}")
        if self.options.subcommand != "network":
            perfdata = (perfdata.strip()).replace(",", ".")
        
        return perfdata



    @staticmethod
    def check_ssh(hostname, port, username, keyfile):
        keyfile = paramiko.RSAKey.from_private_key_file(keyfile)
        ssh = paramiko.SSHClient()
        
        try:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname, port, username, pkey=keyfile, allow_agent=False, look_for_keys=False, timeout=30, banner_timeout=30, auth_timeout=30)
            status = 0
            ssh.close()
            return status
        except:
            print(f"\tCould not connect to {hostname}, please check SSH connection!")
            sys.exit(1)
            


    def run_ssh_command(self, command, hostname, sshport, sshuser, keyfile, email_rcpt=""):
        ssh_status = self.check_ssh(hostname, sshport, sshuser, keyfile)
        keyfile = paramiko.RSAKey.from_private_key_file(keyfile)
        output = ""
        if ssh_status == 0:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(
                    hostname, port=sshport, username=sshuser, pkey=keyfile,
                    allow_agent=False, look_for_keys=False, timeout=30, banner_timeout=30, auth_timeout=30
                )
                stdin, stdout, stderr = ssh.exec_command(command)
                stdin.flush()

                stdout = io.TextIOWrapper(stdout, encoding='utf-8', errors='replace')
                output = (''.join(stdout.readlines()))
            finally:
                ssh.close()
        else:
            self.output(CheckState.WARNING, f"Cannot run remote command ({command}) on {hostname}, please check ssh connection!")
        
        return output


    
    def check_thresholds_scale(self, scale):
        if (self.options.subcommand == "cpu" or self.options.subcommand == "disk-io" or self.options.subcommand == "disk-usage" or self.options.subcommand == "memory" \
            or self.options.subcommand == "network" or self.options.subcommand == "procs" or self.options.subcommand == "services" \
            or self.options.subcommand == "swap") and scale == "increase":
            return(self.options.threshold_warning < self.options.threshold_critical)
               
        elif self.options.subcommand == "disk_health" and scale == "decrease": 
            return(self.options.threshold_critical < self.options.threshold_warning)


    
    def check_cpu(self,perfdata, subcommand):
        cpu_usage = round((float(perfdata)), 2)

        if self.options.threshold_critical <= cpu_usage:
            self.output(CheckState.CRITICAL, f"CPU usage is {cpu_usage} %! | usage={cpu_usage}%;{self.options.threshold_warning};{self.options.threshold_critical};0;100")
        elif  self.options.threshold_warning <= cpu_usage and cpu_usage <= self.options.threshold_critical:
            self.output(CheckState.WARNING, f"CPU usage is {cpu_usage} %! | usage={cpu_usage}%;{self.options.threshold_warning};{self.options.threshold_critical};0;100")
        elif cpu_usage < self.options.threshold_warning:
            self.output(CheckState.OK, f"CPU usage is {cpu_usage} %. | usage={cpu_usage}%;{self.options.threshold_warning};{self.options.threshold_critical};0;100")



    def check_disk_health(self, perfdata, subcommand):

        def string_format(string):
            return ((string.split(":"))[1]).strip()


        disk_list = []
        counter = 0
        disk_list.append([counter])
        disk_datas_list = perfdata.splitlines()

        for element in disk_datas_list:
            if element != "" :
                disk_list[counter].insert(-1, element)
            else:
                counter += 1
                disk_list.append([counter])
             

        for disk in disk_list:
            deviceID = string_format(disk[0])
            model = string_format(disk[1])
            MediaType = string_format(disk[2])
            OperationalStatus = string_format(disk[3])
            HealthStatus = string_format(disk[4])
            Disk_size, UOM = self.check_UOM(int(string_format(disk[5])))
            
            if OperationalStatus != "OK" and HealthStatus != "Healthy":
                self.result_list.append(f"CRITICAL - deviceID {deviceID} - model: {model}, type: {MediaType}, size {Disk_size} {UOM} is failed: OperationalStatus {OperationalStatus}, HealthStatus {HealthStatus}")
            
            else:
                if not any("CRITICAL" in x for x in self.result_list):
                    self.result_list.append(f"OK - All disks are healthy.")

            if any("CRITICAL" in x for x in self.result_list):
                self.result_list = [x for x in self.result_list if re.search("CRITICAL -", x)]

        return set(self.result_list)



    def check_disk_io(self, perfdata, subcommand):
        
        disk_io_details = perfdata.splitlines()
        disk_io_details_list = list(filter(None, disk_io_details))
        disk_io_usage_list = disk_io_details_list[0]
        disk_io_usage_list = disk_io_usage_list.split(" ")
        disk_io_usage_list = list(filter(None, disk_io_usage_list))
        disk_io_usage = int(disk_io_usage_list[1])
        
        if disk_io_usage > 100:
            disk_io_usage = 100
        
        disk_io_app_usage_list = disk_io_details_list[1:]
        disk_io_app_usage_list = [x for x in disk_io_app_usage_list if "_Total" not in x]
        
        if len(disk_io_app_usage_list) > 0:
            disk_io_app_usage_dict = {}
            for disk_io_app_usage in disk_io_app_usage_list:
                disk_io_app_usage_split_list = disk_io_app_usage.split(" ")
                disk_io_app_usage_split_list = list(filter(None,disk_io_app_usage_split_list))

                joined_service_name = ' '.join(disk_io_app_usage_split_list[:-1])
                disk_io_app_usage_dict[joined_service_name] = int(disk_io_app_usage_split_list[-1])

            disk_io_app_usage_sorted_tuple = sorted(disk_io_app_usage_dict.items(), key=lambda x: x[1], reverse=True)
            disk_io_app_usage_sorted_list = []

            for disk_io_app_usage in disk_io_app_usage_sorted_tuple:
                app_usage_string = ' '.join(map(str, disk_io_app_usage))
                disk_io_app_usage_sorted_list.append(app_usage_string)

            app_usage_string = '\n'.join(disk_io_app_usage_sorted_list)
            new_line = '\n'
            
            output = textwrap.dedent(f"{subcommand} usage is {disk_io_usage} %.\
            {new_line}Most disk-io usage processes (IODataOperationsPersec):\
            {new_line}{app_usage_string}\
            |usage={disk_io_usage};{self.options.threshold_warning};{self.options.threshold_critical};0;100")

        else:
            output = f"{subcommand} usage is {disk_io_usage} %.\
                    |usage={disk_io_usage};{self.options.threshold_warning};{self.options.threshold_critical};0;100"


        if self.options.threshold_critical <= disk_io_usage:
            self.output(CheckState.CRITICAL, f"{output}")
        elif  self.options.threshold_warning <= disk_io_usage and disk_io_usage <= self.options.threshold_critical:
            self.output(CheckState.WARNING, f"{output}")
        elif disk_io_usage < self.options.threshold_warning:
            self.output(CheckState.OK, f"{output}")



    def check_disk_usage(self, perfdata, subcommand):
        storage_list_details = perfdata.splitlines()

        def check_storage_inside():
            
            output = f"{drive_letter} ({drive_label}) drive usage is {storage_used_percent} % ({storage_used} {storage_unit} / {storage_total} {storage_unit}).\
                    |{drive_letter}={storage_used}{storage_unit};{storage_used_warning};{storage_used_critical};0;{storage_total}"

            if self.options.threshold_critical <= storage_used_percent:
                self.result_list.append(f"CRITICAL - {output}")
            elif  self.options.threshold_warning <= storage_used_percent and storage_used_percent <= self.options.threshold_critical:
                self.result_list.append(f"WARNING - {output}")
            elif storage_used_percent < self.options.threshold_warning:
                self.result_list.append(f"OK - {output}")

        
        for element in storage_list_details:
            element = element.split(" ")
            element = list(filter(None, element))
            try:
                if len(element[0]) == 1 and element[2] != "0" :
                    
                    match = re.findall(r'^[a-zA-Z]$', element[0])
                    if len(match) == 0:
                        drive_letter = "No drive"
                    else:
                        drive_letter = element[0]

                    storage_free_space = round(((int(element[1]))/1024**3),2)
                    storage_total = round(((int(element[2]))/1024**3),2)
                    storage_used = round((storage_total - storage_free_space),2)
                    storage_unit = "GB"
                    try:
                        drive_label = element[3]
                    except:
                        drive_label = "No label"

                    
                    storage_used_warning = round(((storage_total / 100)*self.options.threshold_warning),2)
                    storage_used_critical = round(((storage_total / 100)*self.options.threshold_critical),2)
                    storage_used_percent = round((storage_used/storage_total)*100,2)

                    
                    if len(self.options.include_drive) > 0:
                        self.options.include_drive = [x.lower() for x in self.options.include_drive]
                        if drive_letter.lower() in (self.options.include_drive):
                            check_storage_inside()

                    else:
                        self.options.ignore_drive = [x.lower() for x in self.options.ignore_drive]
                        if drive_letter.lower() not in self.options.ignore_drive:
                            check_storage_inside()
            except:
                pass


        return self.result_list



    def check_memory(self, perfdata, subcommand):
        memory_list = perfdata.splitlines()
        memory_free = int(memory_list[0])/1024**2
        memory_total = round(((int(memory_list[1]))/1024**2),1)
        memory_used = round((memory_total - memory_free),1)

        memory_used_warning = round(((memory_total /100)*self.options.threshold_warning),2)
        memory_used_critical = round(((memory_total /100)*self.options.threshold_critical),2)

        if memory_total == 0:
            memory_used_percent = round((memory_used/1)*100,2)
        else:
            memory_used_percent = round((memory_used/memory_total)*100,2)

        output = f"{subcommand} usage is {memory_used_percent} % ({memory_used} GB / {memory_total} GB).\
                |usage={memory_used}GB;{memory_used_warning};{memory_used_critical};0;{memory_total}"

        if self.options.threshold_critical <= memory_used_percent:
            self.output(CheckState.CRITICAL, f"{output}")
        elif  self.options.threshold_warning <= memory_used_percent and memory_used_percent <= self.options.threshold_critical:
            self.output(CheckState.WARNING, f"{output}")
        elif memory_used_percent < self.options.threshold_warning:
            self.output(CheckState.OK, f"{output}")



    def check_network(self, perfdata, subcommand):
        nic_dict = {}
        data = json.loads(perfdata)
        
        def fix_encoding(text):
            if isinstance(text, str):
                return text.encode("latin1", "ignore").decode("utf-8", "ignore")
            return text

        for network_adapters in data:
            if "Name" in network_adapters:
                adapter_name = network_adapters["Name"]
            else:
                adapter_name = network_adapters["Description"]
            replace_characters = [",", "/", "#", "[", "]", "(", ")", "_", "{", "}"]
            replace_map = str.maketrans({char: " " for char in replace_characters})
            adapter_name = adapter_name.translate(replace_map)
            adapter_name = " ".join(adapter_name.split())
            
            if isinstance(adapter_name, str):
                adapter_name = fix_encoding(adapter_name)
            elif isinstance(adapter_name, list):
                adapter_name = [fix_encoding(x) for x in adapter_name]
            
            if adapter_name not in nic_dict:
                nic_dict[adapter_name] = {}
            
            if "BytesReceivedPersec" in network_adapters and "MACAddress" not in network_adapters:
                transfer_speed_received = int(network_adapters["BytesReceivedPersec"])
                transfer_speed_sent = int(network_adapters["BytesSentPersec"])
                nic_dict[adapter_name] = {"transfer_speed_received":transfer_speed_received, 
                                        "transfer_speed_sent": transfer_speed_sent}
            elif adapter_name in nic_dict and len(nic_dict[adapter_name]) < 2:
                transfer_speed_received = 0
                transfer_speed_sent = 0
                nic_dict[adapter_name] = {"transfer_speed_received":transfer_speed_received, 
                                        "transfer_speed_sent": transfer_speed_sent}

            if "MACAddress" in network_adapters:
                mac_address = network_adapters["MACAddress"]
                nic_dict[adapter_name]["mac_address"] = mac_address
            
            if "IPAddress" in network_adapters:
                ip_address_list = network_adapters["IPAddress"]
                ipv4_address = ip_address_list[0]
                
                try:
                    ipv6_address = ip_address_list[1]
                except:
                    ipv6_address = None
                nic_dict[adapter_name]["ipv4_address"] = ipv4_address
                nic_dict[adapter_name]["ipv6_address"] = ipv6_address
        
        for adapter_name,nic_details_list in nic_dict.items():
            adapter_name_for_graphite = re.sub(r"[^a-zA-Z0-9 ]", "", adapter_name)
            nic_speed_received = round(((nic_details_list["transfer_speed_received"])/1024**2),2)
            nic_speed_sent = round(((nic_details_list["transfer_speed_sent"])/1024**2),2)
            try:
                mac_address = nic_details_list["mac_address"]
            except:
                mac_address = None
            
            try:
                ipv4_address = nic_details_list["ipv4_address"]
            except:
                ipv4_address = None
            
            try:
                ipv6_address = nic_details_list["ipv6_address"]
            except:
                ipv6_address = None

            output = f"{subcommand} usage is {nic_speed_received}/{nic_speed_sent} MB on '{adapter_name}' (ip: {ipv4_address}/{ipv6_address}, mac: {mac_address}).\
                    |'{adapter_name_for_graphite}_in'={nic_speed_received}MB;{self.options.threshold_warning};{self.options.threshold_critical};0;; '{adapter_name_for_graphite}_out'={nic_speed_sent}MB;{self.options.threshold_warning};{self.options.threshold_critical};0;;"
            
            if self.options.threshold_critical <= nic_speed_received or self.options.threshold_critical <= nic_speed_sent:
                self.result_list.append(f"CRITICAL - {output}")
            elif (self.options.threshold_warning <= nic_speed_received and nic_speed_received <= self.options.threshold_critical) or \
                    (self.options.threshold_warning <= nic_speed_sent and nic_speed_sent <= self.options.threshold_critical):
                self.result_list.append(f"WARNING - {output}")
            elif nic_speed_received < self.options.threshold_warning :
                self.result_list.append(f"OK - {output}")
        
        return self.result_list


    def check_procs(self, perfdata, subcommand):
        procs_count = int(perfdata)

        output = f"process count: {procs_count}. |procs={procs_count};{self.options.threshold_warning};{self.options.threshold_critical};0;;"

        if self.options.threshold_critical <= procs_count:
            self.output(CheckState.CRITICAL, f"{output}")
        elif self.options.threshold_warning <= procs_count and procs_count <= self.options.threshold_critical:
            self.output(CheckState.WARNING, f"{output}")
        elif procs_count < self.options.threshold_warning:
            self.output(CheckState.OK, f"{output}")


    
    def check_swap(self, perfdata, subcommand):
        memory_list = perfdata.splitlines()
        memory_free = int(memory_list[0])
        memory_total = round((int(memory_list[1])),1)
        memory_used = round((memory_total - memory_free),1)

        memory_used_warning = round(((memory_total /100)*self.options.threshold_warning),2)
        memory_used_critical = round(((memory_total /100)*self.options.threshold_critical),2)

        if memory_total == 0:
            memory_used_percent = round((memory_used/1)*100,2)
        else:
            memory_used_percent = round((memory_used/memory_total)*100,2)

        output = f"{subcommand} usage is {memory_used_percent} % ({memory_used} MB / {memory_total} MB).\
                |usage={memory_used}MB;{memory_used_warning};{memory_used_critical};0;{memory_total}"

        if self.options.threshold_critical <= memory_used_percent:
            self.output(CheckState.CRITICAL, f"{output}")
        elif  self.options.threshold_warning <= memory_used_percent and memory_used_percent <= self.options.threshold_critical:
            self.output(CheckState.WARNING, f"{output}")
        elif memory_used_percent < self.options.threshold_warning:
            self.output(CheckState.OK, f"{output}")



    def check_user_logged_on(self, perfdata, subcommand):
        user_number = perfdata.splitlines()
        user_number = (len(user_number))-1
        self.output(CheckState.OK, f"{perfdata}\
                |users={user_number};;;0;;")



    def check_user_count(self, perfdata, subcommand):
        user_list = perfdata.splitlines()
        user_list = [(x).rstrip() for x in user_list]

        if len(self.options.ignore_usernames) > 0:
            user_list = list(set(user_list) - set(self.options.ignore_usernames))
            user_count = len(user_list)
        else:
            user_count = len(user_list)
        
        new_line = '\n'
        user_list.sort()

        output = f"User number is {user_count} (Expected user number: {self.options.threshold_warning})!{new_line}Registered users:{new_line}{new_line.join(str(x.strip()) for x in user_list)}\
                |user number={user_count};{self.options.threshold_warning};;0;"

        if self.options.threshold_warning != user_count and self.options.threshold_warning != None:
            self.output(CheckState.WARNING, f"{output}")
        else: 
            self.output(CheckState.OK, f"{output}")



    def check_winfo(self, perfdata, subcommand):
        winfo_details = perfdata.replace("CSName", "Computer name")
        self.output(CheckState.OK, winfo_details)



    def check_exitcodes(self, result_list):

        if any("CRITICAL" in x for x in result_list):
            [print(x) for x in result_list if re.search("CRITICAL", x)]
        if any("WARNING" in x for x in result_list):
            [print(x) for x in result_list if re.search("WARNING", x)]
        if any("OK -" in x for x in result_list):
            [print(x) for x in result_list if re.search("OK -", x)]
        
    
        if any("CRITICAL" in x for x in result_list):
            sys.exit(2)
        if any("WARNING" in x for x in result_list):
            sys.exit(1)
        
        sys.exit(0)
        


check_win = CheckWin()
check_win.main()
