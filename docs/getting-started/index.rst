.. SPDX-License-Identifier: GPL-3.0-or-later
.. SPDX-FileCopyrightText: Sven Eckelmann <sven@narfation.org>

===============
Getting started
===============

ap51-flash installs a firmware image on a router or access point over an
ethernet cable. It talks directly to the boot loader of the device during the
first seconds after power-on, so it works even when the firmware on the
device is broken or missing. You do not need to configure IP addresses, run a
TFTP server or know the network setup of the device.

This page walks through a complete flashing session. The technical background
is described in :doc:`../how-it-works/index`.


What you need
=============

* A supported device (see :doc:`../supported-devices/index`) and its power
  supply.
* A firmware image built for this device in one of the formats ap51-flash
  understands (see `Which image file to use`_ below).
* A computer with a wired ethernet port. The computer runs Linux, Windows or
  macOS.
* An ethernet cable from the computer directly to the device. Some devices
  must be flashed over a specific port. A direct cable is the most reliable
  setup; a simple unmanaged switch between the two also works. Do not go
  through a router or a managed switch that filters ARP or unknown IP
  subnets.
* Administrator or root privileges on the computer. ap51-flash captures and
  sends raw ethernet frames, which operating systems only permit for
  privileged users.


Getting ap51-flash
==================

Prebuilt binaries
-----------------

Every release ships ready-to-run binaries on the `release page`_:

* ``ap51-flash-<version>-x86_64-linux`` and ``ap51-flash-<version>-i386-linux``
  are statically linked Linux binaries that run on any distribution. Make
  them executable with ``chmod +x``.
* ``ap51-flash-<version>-i686-npcap.exe`` is the Windows binary. It needs the
  Npcap_ packet capture driver, which must be installed first.

Each file comes with a ``.sha256`` checksum and a ``.asc`` GnuPG signature.

Building from source
--------------------

On Linux a C compiler and GNU make are enough::

   git clone https://github.com/ap51-flash/ap51-flash.git
   cd ap51-flash
   make

This produces the binary ``ap51-flash`` in the source directory. On macOS
libpcap is required and the target is::

   make ap51-flash-osx

Windows binaries are cross-compiled from Linux with a MinGW toolchain and the
Npcap or WinPcap SDK::

   make CROSS=i686-w64-mingw32.static- ap51-flash.exe

The firmware image can also be compiled into the binary, which gives a single
file that flashes without any arguments except the interface name. See
`Embedding the image`_ below.


Which image file to use
=======================

ap51-flash does not accept arbitrary firmware files. It reads the header of
the given file to find out for which device family it is and which parts it
has to send. ``ap51-flash -h`` prints the list of accepted formats; currently
these are:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Image type
     - Used for
   * - combined image (``CI``)
     - RedBoot devices: La Fonera, Meraki Mini, D-Link DIR-300, Engenius,
       Ubiquiti RouterStation and other RedBoot boards. Contains kernel and
       root file system in one container.
   * - combined ext image (``CE``)
     - Open Mesh, Plasma Cloud and Datto devices. One container can hold the
       firmware for several models; ap51-flash picks the right part.
   * - u-boot image
     - Open Mesh MR500 and Alfa Network AP121F.
   * - ubiquiti image
     - Ubiquiti Bullet, NanoStation, Pico (the ``.bin`` files Ubiquiti and
       OpenWrt publish for these devices).
   * - Zyxel image
     - Zyxel NBG6817 (the ``ras.bin`` style factory image).

Firmware projects that target these devices usually publish an image in the
matching format; look for *ap51-flash*, *factory* or *combined* in the file
name. A parallel published sysupgrade image for an already running OpenWrt
is often **not** a valid ap51-flash image.

Several images of different types may be passed at once. ap51-flash then
flashes every detected device with the image that fits it. The file is
checked when ap51-flash starts; a wrong or damaged file is rejected before
anything is sent to a device.


Preparing the computer
======================

1. Connect the ethernet cable between the computer and the device. Leave the
   device **powered off** for now.

2. Find the name of the ethernet interface. Running ``ap51-flash`` without
   arguments (or with ``-h``) lists all usable interfaces, each with a number
   and a name::

      1: enp3s0
              (No description available)
      2: wlp2s0
              (No description available)

   On Windows the names are long device GUIDs, so the number is easier to use.
   Either the name or the number is accepted as the interface argument.

3. Make sure the interface is up. ap51-flash refuses to start on an interface
   that is administratively down. On Linux::

      ip link set enp3s0 up

   An IP address is **not** required. If the interface has one, that is fine
   as long as it is not in the ``192.168.1.0/24``, ``192.168.99.0/24`` or
   ``192.168.100.0/24`` range used by the boot loaders. On Linux, NetworkManager
   or similar tools may bring the interface down again when no cable is
   detected; using an unmanaged switch between the powered-off device and the
   computer avoids   that.

4. Stop any TFTP server running on the computer, and on Windows make sure no
   other program (for example a second packet capture tool) holds the Npcap
   adapter exclusively.


Flashing a device
=================

1. Start ap51-flash **before** powering on the device. It needs to see the
   very first packets the boot loader sends::

      sudo ./ap51-flash enp3s0 firmware-ap51.bin

   On Windows, from an administrator command prompt::

      ap51-flash-2026.0-i686-npcap.exe 1 firmware-ap51.bin

   ap51-flash prints nothing and waits. This is normal.

2. Power on the device. Some devices enter the flashing mode of their boot
   loader on every boot for a few seconds; others need a button:

   * **Open Mesh, Plasma Cloud, Datto**: just power on. The boot loader looks
     for ap51-flash during every boot.
   * **Ubiquiti (Bullet, NanoStation, Pico)**: hold the reset button while
     connecting power and keep it pressed for about 8 seconds until the
     signal LEDs blink alternately. This starts the TFTP recovery mode of the
     boot loader. See the `Ubiquiti TFTP recovery`_ page in the OpenWrt wiki.
   * **RedBoot devices**: just power on. RedBoot opens the telnet console for
     a short moment during boot; ap51-flash catches it.
   * **Zyxel NBG6817**: hold the WPS button while powering on. The boot
     loader only listens for about three seconds, so a switch between the
     computer and the device (which keeps the link up) makes this much more
     reliable. See the `Zyxel NBG6817`_ page in the OpenWrt wiki.
   * **Alfa Network AP121F**: just power on.

3. Watch the output. A successful session looks like this::

      [00:11:22:33:44:55]: device type 'OM2P' detected
      [00:11:22:33:44:55]: OM2P: tftp client asks for 'fwupgrade.cfg', serving fwupgrade.cfg-OM2P portion of: firmware-ap51.bin (1 blocks) ...
      [00:11:22:33:44:55]: OM2P: tftp client asks for 'kernel', serving kernel portion of: firmware-ap51.bin (3276 blocks) ...
      [00:11:22:33:44:55]: OM2P: tftp client asks for 'rootfs', serving rootfs portion of: firmware-ap51.bin (7812 blocks) ...
      [00:11:22:33:44:55]: OM2P: image successfully transmitted - writing image to flash ...
      [00:11:22:33:44:55]: OM2P: flash complete. Device ready to unplug.

   The MAC address in brackets identifies the device. The messages differ
   slightly between device types, but every session ends with either
   ``flash complete`` or an error.

4. **Do not interrupt the power** between ``image successfully transmitted``
   and ``flash complete``. During that time the device writes the image to
   its flash memory. Cutting power here can brick the device.

5. After ``flash complete. Device ready to unplug.`` the device reboots into
   the new firmware. Unplug it or wait for it to come up. ap51-flash keeps
   running and will flash the next device plugged into the same cable or
   switch. Stop it with ``Ctrl-C`` when you are done.


Flashing many devices
=====================

ap51-flash keeps a separate state for every device MAC address, so several
devices connected to the same switch are flashed in parallel, and devices can
be swapped one after another without restarting the program.

To restrict flashing to specific devices, pass their MAC addresses with
``-m``. The option can be repeated::

   sudo ./ap51-flash -m 00:11:22:33:44:55 -m 00:11:22:33:44:66 enp3s0 firmware-ap51.bin

Devices that are detected but not on the list are reported and left alone.


Embedding the image
===================

For deployments where other people have to flash devices, the image can be
compiled into the binary::

   make EMBED_CE=/path/to/firmware-ap51.bin DESC="MyFirmware 1.0"

The variable name selects the image type: ``EMBED_CI``, ``EMBED_CE``,
``EMBED_UBOOT``, ``EMBED_UBNT`` or ``EMBED_ZYXEL``. The resulting binary is
started with just the interface name::

   sudo ./ap51-flash enp3s0

``ap51-flash -v`` shows the embedded description. If an image file is given
on the command line anyway, the embedded image is ignored for that run.


Troubleshooting
===============

**Nothing happens after powering on the device.**
  Check that ap51-flash was started before the device, that the cable is in
  the right port of the device, and that the interface is up. Try another
  cable or a direct connection without a switch. Some devices only enter
  flashing mode when a button is held; see the list above. Run
  ``tcpdump -i <interface> -n arp`` in a second terminal: if no ARP packets
  from the device show up, the problem is between the cable and the boot
  loader, not in ap51-flash.

**is of type '...' that we have no image for**
  The device was recognised, but none of the given image files matches it.
  Make sure you downloaded the image for the right model and in the right
  format.

**Error - interface is not up & running**
  Bring the interface up first (``ip link set <interface> up``). On some
  systems the interface stays down until a powered device is attached;
  ap51-flash then has to be started after the cable is live but before the
  boot loader starts, which is hard to time. A switch between the computer
  and the device keeps the link up permanently and avoids this.

**Error - can't create raw socket: Operation not permitted**
  ap51-flash needs root privileges (or ``CAP_NET_RAW`` and
  ``CAP_NET_ADMIN``). Run it with ``sudo``.

**Unable to load Npcap library** (Windows)
  Install Npcap_ and start a new administrator command prompt.

**tftp client asks for '...' - file not found**
  The boot loader requests a file name the image does not contain. This
  typically means the image was built for a different device variant, or the
  image format is not the one the boot loader expects.

**received TFTP error** or **tftp acks unsent block**
  Usually a second TFTP server or client on the computer interferes. Stop it
  and try again. A faulty cable or a switch that drops packets causes similar
  symptoms.

**The device was flashed but does not boot.**
  ap51-flash only transports the image; it cannot check whether the image
  works on the device. Flash again with a known good image. For RedBoot
  devices the ``flash complete`` message means the ``reset`` command was sent;
  if the new firmware does not come up, the kernel or root file system in the
  image does not fit the device.

If you are stuck, report the exact output of ap51-flash together with a
packet capture (see :doc:`../how-it-works/index`) on the
`issue tracker`_.


.. _release page: https://github.com/ap51-flash/ap51-flash/releases
.. _Ubiquiti TFTP recovery: https://openwrt.org/docs/guide-user/installation/recovery_methods/ubiquiti_tftp
.. _Zyxel NBG6817: https://openwrt.org/toh/zyxel/nbg6817
.. _Npcap: https://npcap.com/
.. _issue tracker: https://github.com/ap51-flash/ap51-flash/issues
