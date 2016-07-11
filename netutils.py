#! /usr/bin/env python
#
# Network utilities for Python, version 1.4.
# Copyright 2010-2012 by Akkana Peck akkana@shallowsky.com
# ... share and enjoy under the GPLv2 or (at your option) later.

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

    def ifconfig_up(self):
        """Mark the interface UP with ifconfig"""

        # Okay, I have no idea what's going on here.
        # If I set an eth0 scheme (which works correctly),
        # then later try to set a wlan0 WPA scheme,
        # when we get here, all interfaces are properly down.
        # ifconfig -a shows that.
        # Then we call ifconfig wlan0 up,
        # and immediately after that, another ifconfig -a
        # shows that both wlan0 and eth0 have been marked up.
        # How do we mark wlan0 up without bringing eth0 with it?
        # Running ifconfig wlan0 up by hand doesn't do that.
        subprocess.call(["/sbin/ifconfig", self.name, "up"])

    def ifconfig_down(self):
        """Mark the interface DOWN with ifconfig"""
        # It is not enough to just mark it down -- networking
        # will still try to use it if it has an IP address configured.
        # So remove that too.
        # Doing it through ifconfig doesn't seem to work, so use ip.
        subprocess.call(["ip", "addr", "flush", "dev", self.name])
        # and then mark it down with ifconfig.
        subprocess.call(["ifconfig", self.name, "down"])
        self.reload()

    def is_up(self):
        # Old format: '          UP BROADCAST MULTICAST  MTU:1500  Metric:1'
        # New format: 'wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        proc = subprocess.Popen(["/sbin/ifconfig", self.name],
                                shell=False, stdout=subprocess.PIPE)
        stdout_lines = proc.communicate()[0].split('\n')
        for line in stdout_lines:
            if len(line) == 0:
                continue
            if line[0] == ' ':
                words = line.strip().split()
                if words[0] == 'UP':
                    return True
            elif 'flags=' in line and 'UP,' in line:
                return True

        # Didn't see any UP line.
        return False

    def check_associated(self):
        '''Are we associated with an ESSID? Return the essid name, or None.
        '''
        proc = subprocess.Popen("iwconfig %s" % self.name, shell=True,
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
        proc = subprocess.Popen('route -n', shell=True, stdout=subprocess.PIPE)
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
       Omit lo, vpn, ipv6 and other non-physical interfaces.
       If only_up is true, use ifconfig instead if ifconfig -a.
       If name is specified, return only the first matching that name.
    """
    if name:
      ifcfg = "ifconfig " + name
    elif only_up:
        ifcfg = 'ifconfig'
    else:
        ifcfg = '/sbin/ifconfig -a'
        #ifcfg = 'cat /home/akkana/ifconfig.arch'
    proc = subprocess.Popen(ifcfg, shell=True, stdout=subprocess.PIPE)
    stdout_str = proc.communicate()[0]
    stdout_list = stdout_str.split('\n')
    ifaces = []
    cur_iface = None
    for line in stdout_list:
        if len(line) == 0:
            continue
        words = line.split()
        if line[0] != ' ':
            # It's a new interface. Should have a line like:
            # eth0      Link encap:Ethernet  HWaddr 00:01:4A:98:F1:51
            # or else a line line:
            # flags=4098<BROADCAST,MULTICAST>
            # with no LOOPBACK flag.
            # We only want the encap:Ethernet lines, not others like
            # loopback, vpn, ipv6 etc.
            if words[2] == 'encap:Ethernet' or \
                    words[1].startswith('flags') and not 'LOOPBACK' in words[1]:
		if words[0].endswith(':'):
		    words[0] = words[0][0:-1]
                cur_iface = NetInterface(words[0])
                ifaces.append(cur_iface)
                        
            else:
                cur_iface = None
        else:
            if not cur_iface:
                continue
            if words[0] == 'inet':
                # Old format:
                # inet addr:192.168.1.6  Bcast:192.168.1.255  Mask:255.255.255.0
                match = re.search('addr:(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    cur_iface.ip = match.group(1)
                match = re.search('Bcast:(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    cur_iface.broadcast = match.group(1)
                match = re.search('Mask:(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    cur_iface.netmask = match.group(1)
                # New format:
                # inet 127.0.0.1  netmask 255.0.0.0
                match = re.search('inet (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    cur_iface.ip = match.group(1)
                match = re.search('netmask (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    cur_iface.netmask = match.group(1)
                match = re.search('ether (..:..:..:..:..:..)', line)
                if match:
                    cur_iface.mac = match.group(1)

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
    if not iface.is_up():
        iface.ifconfig_up()
        if not iface.is_up():
            print "Failed to bring", iface, "up. Bailing."
            return None
    else:
        print iface, "is already up"

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

    # It's apparently better to kill wpa_supplicant while the
    # interface is still up (which takes it down).
    # So now, finally, we can take everything down:
    for iface in up_ifaces:
        print "Marking", iface.name, "down"
        iface.ifconfig_down()

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

