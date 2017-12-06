=================
Supported devices
=================

In general you can flash all devices which use the redboot bootloader that has
the reflashing function enabled. ap51-flash will automatically detect redboot
when you turn on the device. If your device is not in the "known to work" list
which follows you still can try it and inform us about the result.


redboot devices
===============

* FON, La Fonera (2100)
* Open Mesh, OM1P
* Engenius, EOC-1650, EOC-2610, EOC-2610p
* Engenius, 3660
* Dlink, DIR-300 (after installing a reflash-enabled redboot)
* Ubiquiti, Pico2 & HP
* UniAppliance Colibrì (!UniData)


tftp flash
==========

ap51-flash also supports plain tftp flashing without redboot. This method is
quite common amongst a variety of devices.

List of known to work tftp devices:

* Ubiquiti, NanoStation2
* Ubiquiti, NanoStation5
* Ubiquiti, Bullet2 & HP
* Ubiquiti, RouterStation


u-boot flashit
==============

List of known to work uboot devices:

* OpenMesh

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
  - OM2P (v1, v2, v4)
  - OM2P-HS (v1, v2, v3, v4)
  - OM2P-LC
  - OM5P
  - OM5P-AN
  - OM5P-AC (v1, v2)

other devices
=============

There are many different devices out there which differ slighty in their way of
doing things. Even if your device does not work out of the box it might require
only small changes to support it.
