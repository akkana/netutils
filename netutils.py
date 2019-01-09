#! /usr/bin/env python
#
# Network utilities for Python, version 1.4.
# Copyright 2010-2012 by Akkana Peck akkana@shallowsky.com
# ... share and enjoy under the GPLv2 or (at your option) later.

# Some newer libraries that this could potentially use instead of
# parsing ifconfig or ip output:
# https://xmine128.tk/Software/Python/netlink/docs/
# https://pypi.python.org/pypi/netutils-linux/
# https://github.com/svinota/pyroute2

"""netutils: a set of networking utilities for Python.
Copyright 2010 by Akkana Peck <akkana@shallowsky.com>
 ... share and enjoy under the GPLv2 or (at your option) later.

Provides the following:

Classes:
  NetInterface: name, ip, broadcast, netmask, essid, encryption, wireless
  AccessPoint: address, essid, encryption, quality, interface
  Route: display or change network routing tables.

Functions outside of classes:
  get_interfaces(only_up=False): returns a list of all NetInterface.
    If only_up, will only return the ones currently marked UP.
  get_wireless_interfaces(): returns a list of wireless NetInterface.
  get_accesspoints(): returns a list of visible AccessPoints.
  ifdown_all(): take all interfaces down, killing any wpa_supplicant or dhcp
  kill_by_name(namelist): Kill a any running processes that include any
    of the names in namelist. Return a list of actual process names killed.
"""

import sys, os, subprocess, re, shutil, time

class NetInterface:
    """A network interface, like eth1 or wlan0."""

    def __init__(self, name):
        # Debian derivatives sometimes sneakily give names like wlan:avahi.
        # We only want the part before the colon.
        self.name = name.split(':')[0]
        self.ip = ''
        self.broadcast = ''
        self.netmask = ''
        self.essid = ''
        self.encryption = None
        self.wireless = False
        self.mac = ''
        self.up = False

    def __repr__(self):
        """Prettyprint a NetInterface instance"""
        s = 'NetInterface ' + self.name
        if self.wireless:
            if self.essid:
                if self.encryption:
                    s += ' (wireless, essid=%s, %s)' % \
                        (self.essid, self.encryption)
                else:
                    s += ' (wireless, essid=%s, open)' % self.essid
            else:
                s += ' (wireless)'
        if self.is_up():
            s += ' UP'
        if self.ip:
            s += ' ip=' + self.ip
        if self.broadcast:
            s += ' broadcast=' + self.broadcast
        if self.netmask:
            s += ' ip=' + self.netmask

        return s

    def reload(self):
        print "Not reloading: let's see if wpa_supplicant has been fixed"
        return

        try:
            # Sometimes the device doesn't exist. I have no idea why.
            fp = open("/sys/class/net/" + self.name + "/device/uevent")
            # Another way to get this: ethtool -i self.name
        except:
            print "Not resetting: couldn't open device /sys/class/net/" \
                + self.name
            return

        line = fp.readline()
        fp.close()
        if line[0:7] == "DRIVER=":
            module = line[7:].strip()
            print "Unloading", module, "module"
            subprocess.call(["modprobe", "-r", module])
            print "Re-loading", module, "module"
            subprocess.call(["modprobe", module])

            # But reloading often causes the interface to change names:
            # it randomly jumps between names like wlp2s0 and wlan0.
            # So after reloading, it's crucial to find the new name.
            # On a system with multiple wlan interfaces, this is
            # fraught with difficulty, so make a note of the MAC
            # address first and make sure we're addressing the same device.

    def ifconfig_up(self):
        """Mark the interface UP with ifconfig or ip"""

        # subprocess.call(["/sbin/ifconfig", self.name, "up"])
        subprocess.call(["/bin/ip", "link", "set", "dev", self.name, "up"])

    def ifconfig_down(self):
        """Mark the interface DOWN with ifconfig or ip"""
        # It is not enough to just mark it down -- networking
        # will still try to use it if it has an IP address configured.
        # So remove that too.
        # Doing it through ifconfig doesn't seem to work, so use ip.
        subprocess.call(["ip", "addr", "flush", "dev", self.name])
        # and then mark it down:
        # subprocess.call(["ifconfig", self.name, "down"])
        subprocess.call(["/bin/ip", "link", "set", "dev", self.name, "down"])

        self.reload()

    def is_up(self):
        # Old format: '          UP BROADCAST MULTICAST  MTU:1500  Metric:1'
        # New format: 'wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        # ip format: 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
        proc = subprocess.Popen(["/bin/ip", "a", "show", self.name],
                                shell=False, stdout=subprocess.PIPE)
        stdout_lines = proc.communicate()[0].split('\n')
        words = stdout_lines[0].strip().split()
        if not words:
            raise RuntimeError("No interface " + self.name)
        if not words[1].startswith(self.name):
            raise RuntimeError("Couldn't parse ip line: '%s'" % stdout_lines[0])
        if not words[2].startswith('<') or not words[2].endswith('>'):
            raise RuntimeError("Couldn't parse ip flags '%s'" % words[2])
        flags = words[2][1:-1].split(',')
        return 'UP' in flags

    def check_associated(self):
        '''Are we associated with an ESSID? Return the essid name, or None.
        '''
        proc = subprocess.Popen(["iwconfig", self.name], shell=False,
                                stdout=subprocess.PIPE)
        stdout_str = proc.communicate()[0]
        stdout_list = stdout_str.split('\n')
        ifaces = []
        essid = None
        for line in stdout_list:
            if 'Not-Associated' in line:
                print "Not associated"
                return None
            if 'ESSID:' not in line:
                continue
            match = re.search('ESSID:"(.+)"', line)
            if match:
                essid = match.group(1).strip('"')

        return essid

class AccessPoint:
    """ One Cell or AccessPoint from iwlist output"""

    def __init__(self):
        self.clear()

    def clear(self):
        """Clear all parameters"""
        self.address = ""
        self.essid = ""
        self.encryption = ""
        self.quality = ""
        self.interface = ""
        self.mode = ""

class Route:
    """Network routing table entry: one line from route -n"""

    # Route(line)
    # Route(dest, gateway, iface, mask=None):
    def __init__(self, *args):
        if len(args) == 1:
            self.init_from_line(args[0])
            return

        (self.dest, self.gateway, self.iface) = args
        if len(args) > 3:
            self.mask = args[3]

    def init_from_line(self, line):
        """init from a line from route -n, such as:
192.168.1.0     *               255.255.255.0   U         0 0          0 eth0
default         192.168.1.1     0.0.0.0         UG        0 0          0 wlan0
        """
        # Another place to get this is /proc/net/route.

        words = line.split()
        if len(words) < 8:
            self.dest = None
            return
        self.dest = words[0]
        if self.dest == 'Destination':
            self.dest = None
            return
        self.gateway = words[1]
        self.mask = words[2]
        self.iface = words[7]

    def __repr__(self):
        """Return a string representing the route"""
        return "dest=%-16s gw=%-16s mask=%-16s iface=%s" % (self.dest,
                                                            self.gateway,
                                                            self.mask,
                                                            self.iface)

    def call_route(self, cmd):
        """Backend routine to call the system route command.
           cmd is either "add" or "delete".
           Users should normally call add() or delete() instead."""
        args = [ "route", cmd ]

        # Syntax seems to be different depending whether dest is "default"
        # or not. The man page is clear as mud and explains nothing.
        if self.dest == 'default' or self.dest == '0.0.0.0':
            # route add default gw 192.168.1.1
            # route del default gw 192.168.160.1
            # Must use "default" rather than "0.0.0.0" --
            # the numeric version results in "SIOCDELRT: No such process"
            args.append("default")
            if self.gateway:
                args.append("gw")
                args.append(self.gateway)
        else:
            # route add -net 192.168.1.0 netmask 255.255.255.0 dev wlan0
            args.append('-net')
            args.append(self.dest)
            if self.gateway:
                args.append("gw")
                args.append(self.gateway)
            if self.mask:
                args.append("mask")
                args.append(self.mask)
        args.append("dev")
        args.append(self.iface)

        print "Calling:", args
        subprocess.call(args)

    def add(self):
        """Add this route to the routing tables."""
        self.call_route("add")

    def delete(self):
        """Remove this route from the routing tables."""
        # route del -net 192.168.1.0 netmask 255.255.255.0 dev wlan0
        self.call_route("del")

    @classmethod
    def read_route_table(cls):
        """Read the system routing table, returning a list of Routes."""
        proc = subprocess.Popen(["route",  "-n"], shell=False,
                                stdout=subprocess.PIPE)
        stdout_str = proc.communicate()[0]
        stdout_list = stdout_str.split('\n')

        rtable = []
        for line in stdout_list:
            r = Route(line)
            if r.dest:
                rtable.append(r)

        return rtable

def get_interfaces(only_up=False, name=None):
    """Returns a list of NetInterfaces for all eth*, wlan* or mlan*
       interfaces visible from ifconfig.
       Read ip, mac, broadcast, netmask if available.
       Omit lo, vpn, ipv6 and other non-physical interfaces.
       If only_up is true, use ifconfig instead if ifconfig -a.
       If name is specified, return only the first matching that name.
    """
    args = ["/bin/ip", "addr", "show"]
    if name:
        args.append(name)
    if only_up:
        args.append("up")

    proc = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE)
    stdout_lines = proc.communicate()[0].split('\n')

    # For some unknown reason, sometimes wlan0 mysteriously shows up
    # in ip addr show, even though it no longer exists.
    # Need to know exactly what it says in these cases, but since
    # we don't get an exception thrown until later when we try to
    # parse the interfaces, print out the whole thing now.
    #
    # Here's an example of bogus output:
    '''
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
9: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
    link/ether dc:85:de:31:6c:97 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::de85:deff:fe31:6c97/64 scope link 
       valid_lft forever preferred_lft forever
=== (end of ip addr show output)
Taking up interfaces down: [NetInterface wlan0 (wireless) UP]
Killing dhcp processes
Killing wpa processes
Unloading wl module
Re-loading wl module
Marking wlan0 down
Cannot find device "wlan0"
Not resetting: couldn't open device /sys/class/net/wlan0
Cannot find device "wlan0"
=== ip addr show said:
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
10: enp3s0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast state DOWN group default qlen 1000
    link/ether 74:d0:2b:71:7a:3e brd ff:ff:ff:ff:ff:ff
11: wlp2s0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether dc:85:de:31:6c:97 brd ff:ff:ff:ff:ff:ff
=== (end of ip addr show output)

wlp2s0 is wireless
Unloading alx module
Re-loading alx module
Found 5 accesspoints
========= Calling ['iwconfig', 'wlan0', 'essid', 'SOME ESSID', 'mode', 'managed', 'key', 'off', 'channel', 'auto']
Error for wireless request "Set ESSID" (8B1A) :
    '''

    print "=== ip addr show said:"
    print "\n".join(stdout_lines)
    print "=== (end of ip addr show output)"

    ifaces = []
    cur_iface = None

    # Interfaces start with a number, like 2:, followed by the iface name.
    # All other lines start with a space.
    for i, line in enumerate(stdout_lines):
        if len(line) == 0:
            continue

        if line[0].isdigit():
            # It's a new interface.
            # Check the next line to see if it's link/ether.
            nextline = stdout_lines[i+1]
            if not nextline.startswith(' '):
                raise(RuntimeError("""
Problem parsing ip link: second line didn't start with a space
First line: %s
Second line: %s""" % (line, nextline)))
            if not nextline.strip().startswith("link/ether"):
                cur_iface = None
                continue

            # Now we're looking at a valid interface line, e.g.
            # 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
            words = line.split()
            ifacename = words[1]
            if ifacename.endswith(':'):
                ifacename = ifacename[:-1]
            cur_iface = NetInterface(ifacename)

            # XXX maybe should look for UP in flags

            ifaces.append(cur_iface)
            continue

        if line[0] != ' ':
            print("Eek, confusing line '%s'" % line)
            continue

        # It's a continuation line starting with a space.
        # Glean what info we can.
        # A typical entry:
        # 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
        #     link/ether 00:26:2d:f1:0c:7e brd ff:ff:ff:ff:ff:ff
        #     inet 192.168.1.96/24 brd 192.168.1.255 scope global eth0
        #        valid_lft forever preferred_lft forever
        #     inet6 fe80::226:2dff:fef1:c7e/64 scope link 
        #        valid_lft forever preferred_lft forever

        if not cur_iface:
            continue

        words = line.strip().split()

        if words[0] == "link/ether":
            cur_iface.mac = words[1]
        elif words[0] == 'inet':
            cur_iface.ip = words[1]
            if words[2] == 'brd':
                cur_iface.broadcast = words[3]
            # We don't seem to be able to get the netmask with ip.
            # Does it matter?

    # Now we have the list of all interfaces. Find out which are wireless:
    proc = subprocess.Popen('iwconfig', shell=False,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout_str = proc.communicate()[0]
    stdout_list = stdout_str.split('\n')
    cur_iface = None
    for line in stdout_list:
        if len(line) == 0:
            continue
        if line[0] != ' ':
            words = line.split()
            #print "Wireless interface", words[0]
            for iface in ifaces:
                #print "Checking", words[0], "against", iface.name
                if iface.name == words[0]:
                    #print "It's in the list"
                    cur_iface = iface
                    cur_iface.wireless = True
                    match = re.search('ESSID:"(.*)"', line)
                    if match:
                        cur_iface.essid = match.group(1)
                        # print "And it has essid", iface.essid

    # If name was specified, return only that single interface:
    if name:
        if len(ifaces) <= 0 or ifaces[0].name != name:
            return None
        return ifaces[0]

    return ifaces

def get_wireless_interfaces():
    """Returns a list of wireless interfaces available.
    """
    wifaces = []
    for iface in get_interfaces():
        if iface.wireless:
            wifaces.append(iface)
    return wifaces

def get_first_wireless_interface():
    """Returns the first available wireless interface
    """
    wifaces = []
    for iface in get_interfaces():
        if iface.wireless:
            return iface
    return None

def get_accesspoints():
    """Return a list of visible wireless accesspoints."""

    # We can only get accesspoints if a wifi interface is up.
    # But we want the *last* wireless interface, not the first.
    newly_up = None
    ifaces = get_interfaces()
    # print "Got interfaces:", ifaces

    wiface = None
    for iface in ifaces:
        if iface.wireless:
            wiface = iface
            print iface.name, "is wireless"

    if not wiface:
        print "No wireless interface available! Interfaces were", ifaces
        print "Is the interface's driver loaded?"
        return None

    # See if other interfaces are marked UP.
    for iface in ifaces:
        if iface != wiface and iface.is_up():
            iface.ifconfig_down()

    iface = wiface
    try:
        if not iface.is_up():
            iface.ifconfig_up()
            if not iface.is_up():
                print "Failed to bring", iface, "up. Bailing."
                return None
        else:
            print iface, "is already up"
    except RuntimeError, e:
        print "Can't check interface", iface, ":", e
        print "ip addr show may be giving us bogus info"

    proc = subprocess.Popen(['iwlist', iface.name, 'scan'],
                            shell=False, stdout=subprocess.PIPE)
    stdout_str = proc.communicate()[0]
    # print "iwlist said:\n" + stdout_str
    stdout_list = stdout_str.split('\n')

    iface = None
    ap = None
    aplist=[]

    for line in stdout_list:
        if len(line) == 0:
            continue
        if not line[0].isspace():
            sp = line.find(' ')
            if sp > 0:
                iface = line[:sp]
            else:
                iface = line
            continue

        line=line.strip()

        match = re.search('Cell ', line)
        if match:
            ap = AccessPoint()
            aplist.append(ap)
            if iface:
                ap.interface = iface

        match = re.search('ESSID:"(.+)"', line)
        if match:
            if match.group(1) == "<hidden>":
                ap.essid = ''
            # I have no idea what these \x00\x00\x00\x00\x00 essids are,
            # but they're quite common, and annoying to see in a UI:
            elif match.group(1) == "\\x00\\x00\\x00\\x00\\x00":
                ap.essid = "[null]"
            else:
                ap.essid = match.group(1)

        match = re.search('Address: (\S+)', line)
        if match:
            ap.address = match.group(1)

        match = re.search('Encryption key:([onf]+)', line)
        if match:
            if match.group(1) == "off":
                ap.encryption = "open"
            else:
                ap.encryption = "WEP"   # change later if WPA

        # match = re.search('Protocol:IEEE(.+)', line)
        # if match:
        #     ap.protocol = match.group(1)

        match = re.search('WPA', line)
        if match:
            ap.encryption = "WPA"

        match = re.search('Mode:(.+)', line)
        if match:
            ap.mode = match.group(1)

        match = re.search('Quality=([^ ]+) ', line)
        if match:
            ap.quality = match.group(1)

    # If we marked an interface up just for this, mark it down again.
    # But that means reloading the module again, so skip this for now.
    # if newly_up:
    #     print "Take the interface back down now"
    #     newly_up.ifconfig_down()

    print "Found", len(aplist), "accesspoints"
    return aplist

def ifdown_all():
    """Take all current interfaces down.
    """
    print "ifdown_all"
    up_ifaces = get_interfaces(True)
    print "Taking up interfaces down:", up_ifaces

    # Kill DHCP and wpa_supplicant.
    # In theory apparently it's better to stop wpa_supplicant with
    #os.system('wpa_cli -i %s terminate' % up_iface)
    # except for the minor problem that it fails because
    # it can't communicate with wpa_supplicant.
    print "Killing dhcp processes"
    kill_by_name(['dhcpcd', 'dhclient'])

    # Kill wpa_supplicant in a separate step,
    # to make it easier to tell whether it was actually running:
    print "Killing wpa processes"
    killed = kill_by_name(['wpa_supplicant'])

    # It's apparently better to kill wpa_supplicant while the
    # interface is still up (which takes it down).
    # But we can't mark it down after unloading the module,
    # so mark them all down first:
    for iface in up_ifaces:
        print "Marking", iface.name, "down"
        iface.ifconfig_down()

    # If wpa_supplicant was one of the killed processes,
    # then our wireless interface is all messed up now,
    # and we'll never be able to connect to an open or WEP
    # network with that interface again.
    # The only way to fix it seems to be to unload and reload
    # the wireless card's module. If it's not a module ... oops.
    # First find the module:
    if len(up_ifaces) > 0:    # and len(killed) >= 1
        # Get the first wireless one. Hope there's only one.
        iface = None
        for i in up_ifaces:
            if i.wireless:
                iface = i
                break
        if iface:
            iface.reload()
        else:
            print "Confusion! Can't find the old wireless interface to reload"

    elif len(killed) == 0:
        print "Didn't kill wpa, no no need to reload modules"
    else:
        print "Didn't have any UP interfaces"

def kill_by_name(namelist):
    """Kills all running processes that start with any of the
        strings in the given name list.
    """
    PROCDIR = '/proc'
    killed = []
    for proc in os.listdir(PROCDIR):
        if not proc[0].isdigit():
            continue
        # Race condition: processes can come and go, so we may not be
        # able to open something just because it was there when we
        # did the listdir.
        try:
            procfp = open(os.path.join(PROCDIR, proc, 'cmdline'))
            for line in procfp:
                cmd = os.path.basename(line.split('\0')[0])
                for name in namelist:
                    if name == cmd[0:len(name)]:
                        killed.append(name)
                        os.kill(int(proc), 9)
                break    # There's only one line anyway
            procfp.close()
        except:
            pass
    return killed

# main
if __name__ == "__main__":
    print "All interfaces:"
    for iface in get_interfaces():
        print iface
    print "Wireless interfaces:"
    for iface in get_wireless_interfaces():
        print iface

