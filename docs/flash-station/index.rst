.. SPDX-License-Identifier: GPL-3.0-or-later
.. SPDX-FileCopyrightText: Linus Lüssing <linus.luessing@c0d3.blue>

==============================
ap51-flash station for OpenWRT
==============================

OpenWRT-package
===============

* :download:`Makefile`
* files/:download:`ap51-flash.conf`
* files/:download:`ap51-flash.init`


Example configuration of a Dlink DIR-300 as a ap51-flash station
================================================================

* minimal :download:`.config`-file (kicking out a lot of the standard
  applications and modules to save as much RAM as possible and adding
  nfs-support for remote images)
* /etc/config/:download:`network` (configuring ports 1-4 as seperate VLANS for
  flashing other devices and the WAN-port as the adminstration port)
* /etc/:download:`fstab` (for mounting nfs-shares at boot time)

Example image (using the same config as stated above):

 * http://x-realis.dyndns.org/Freifunk/firmware/ap51-flash-station/

2-port-vlan without host learning (hub-mode, for debugging ap51-flash)

* /etc/config/:download:`network2`
* /etc/init.d/:download:`switch-2-hub`
