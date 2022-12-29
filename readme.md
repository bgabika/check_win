
# check_win

COREX Windows host agentless check plugin for Icinga 2, v1.14
 
### Features
 - checks Windows host over SSH
 - prints performance data for Icinga 2 Graphite Module ( and other solutions like Graphite )
 - available subcommands: cpu, disk-health, disk-io, disk-usage, memory, network, procs, swap, user-logged-on, user-count, winfo
 - warning/critical thresholds for each separate subcommands
 - for more details run check_win.py --help

### Usage

<pre><code>
# cd /usr/lib/nagios/plugins
# ./check_win.py --hostname mywin.mydomain.com --sshuser john.doe --sshkey /var/lib/nagios/.ssh/idrsa.pub --subcommand cpu --warning 70 --critical 90 
OK - CPU usage is 14.5 %. | usage=14.5%;70;90;0;100
#
</code></pre>

<pre><code>
# cd /usr/lib/nagios/plugins
# ./check_win.py --hostname mywin.mydomain.com --sshuser john.doe --sshkey /var/lib/nagios/.ssh/idrsa.pub --subcommand disk-usage --warning 80 --critical 90
WARNING - C (No label) drive usage is 82.17 % (188.94 GB / 229.95 GB).                    |C=188.94GB;183.96;206.96;0;229.95
OK - D (backup) drive usage is 0.26 % (0.13 GB / 50.0 GB).                    |D=0.13GB;40.0;45.0;0;50.0
#

</code></pre>



### Version

 - v1.14

### ToDo

 - waiting for bugs or feature requests (-:

## Changelog

 - version v1.14: add new feature: disk-io. Checks disk I/O usage and most disk-IO usage processes.
 - [initial release] version 1.13

