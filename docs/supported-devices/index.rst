.. SPDX-License-Identifier: GPL-3.0-or-later
.. SPDX-FileCopyrightText: 2013, Saverio Proto <zioproto@gmail.com>
.. SPDX-FileCopyrightText: 2013-2019, Marek Lindner <mareklindner@neomailbox.ch>
.. SPDX-FileCopyrightText: 2018, Antonio Quartulli <a@unstable.cc>
.. SPDX-FileCopyrightText: 2017-2019, Sven Eckelmann <sven@narfation.org>

=================
Supported devices
=================

In general you can flash all devices which use the redboot bootloader that has
the reflashing function enabled. ap51-flash will automatically detect redboot
when you turn on the device. If your device is not in the "known to work" list
which follows you still can try it and inform us about the result.

ap51-flash also supports plain tftp flashing without redboot. This method is
quite common amongst a variety of devices.


Tested
======

* Alfa Network

  - AP121F

* Dlink

  - DIR-300 (after installing a reflash-enabled redboot)

* Engenius

  - EOC-1650
  - EOC-2610
  - EOC-2610p
  - 3660

* FON

  - La Fonera (2100)

* Open Mesh

  - A40
  - A42
  - A60
  - A62
  - D200
  - G200
  - MR500
  - MR600 (v1, v2)
  - MR900 (v1, v2)
  - MR1750 (v1, v2)
  - OM1P
  - OM2P (v1, v2, v4)
  - OM2P-HS (v1, v2, v3, v4)
  - OM2P-LC
  - OM5P
  - OM5P-AN
  - OM5P-AC (v1, v2)

* Plasma Cloud

  - PA1200
  - PA2200

* Ubiquiti

  - Bullet2 & HP
  - NanoStation2
  - NanoStation5
  - Pico2 & HP
  - RouterStation

* UniAppliance

  - Colibrì (!UniData)

* Zyxel

  - NBG6817


Other Devices
=============

There are many different devices out there which differ slighty in their way of
doing things. Even if your device does not work out of the box it might require
only small changes to support it.
