.. SPDX-License-Identifier: CC0-1.0
.. SPDX-FileCopyrightText: Sven Eckelmann <sven@narfation.org>

==========
ap51-flash
==========

.. image:: https://img.shields.io/coverity/scan/14627.svg
   :target: https://scan.coverity.com/projects/ap51-flash-ap51-flash
.. image:: https://img.shields.io/readthedocs/ap51-flash.svg
   :target: https://ap51-flash.readthedocs.io/
.. image:: https://img.shields.io/travis/ap51-flash/ap51-flash/master.svg
   :target: https://travis-ci.org/ap51-flash/ap51-flash

firmware flasher for ethernet connected routers and access points

ap51-flash is a tool to simplify the automatic firmware deployment for a
multitude of home routers and wireless access points.

ap51-flash can identify target device(s), select the correct firmware image
and perform the required communication to carry out the installation
procedure. It works without the need for a local TFTP server or manual, target
device specific network configuration.

It does this by listening on the raw ethernet interface for the ARP packets
the boot loaders of supported devices send out after power-on, and by
answering them with handcrafted ARP, TFTP, telnet (RedBoot) or U-Boot
netconsole packets. The IP stack of the host is not used. A packet-level
description of each flashing method can be found in the documentation:
https://ap51-flash.readthedocs.io/en/latest/how-it-works/

See https://ap51-flash.readthedocs.io/ for more information.
