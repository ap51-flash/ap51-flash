.. SPDX-License-Identifier: GPL-3.0-or-later
.. SPDX-FileCopyrightText: Sven Eckelmann <sven@narfation.org>

============
How it works
============

ap51-flash is not a TFTP server and not a telnet client in the usual sense.
It is a packet sniffer combined with a packet injector. It opens the given
ethernet interface in promiscuous mode, watches every frame that arrives and
answers selected frames by handcrafting complete ethernet frames (ARP, IPv4,
UDP/TFTP, TCP/telnet, ICMP) itself. The IP stack of the host operating system
is never involved. This is why the interface does not need an IP address and
why no TFTP daemon has to be installed.

From the point of view of the device being flashed, ap51-flash looks like a
second host on the cable with its own MAC address and the IP address the
device's boot loader expects to find there.

This page describes exactly which frames go over the ethernet cable, in which
order, for each of the four flashing methods ap51-flash implements.


Overview of a flashing session
==============================

Every session goes through the same three phases:

1. **Detection** -- ap51-flash waits for ARP frames that supported boot
   loaders send out automatically shortly after power-on. The content of the
   ARP frame identifies the device type and tells ap51-flash which IP address
   the boot loader will talk to.

2. **Impersonation** -- ap51-flash picks a MAC address of its own
   (``00:ba:be:ca:ff:xx``, the last byte is incremented for every detected
   device) and adopts the IP address the device asked for. From now on it
   answers ARP requests and ICMP echo requests for that address, so the device
   believes a real host is there.

3. **Transfer and flashing** -- the firmware is moved to the device with TFTP
   (`RFC 1350`_) and the device is told to write it to flash. How this happens
   depends on the flash mode that was selected during detection (see below).

ap51-flash keeps one state machine per device MAC address, so several devices
plugged into the same switch can be flashed simultaneously.


Interface access
================

* **Linux**: a ``PF_PACKET``/``SOCK_RAW`` socket bound to the interface with
  ``ETH_P_ALL``. Promiscuous mode is requested with a ``PACKET_MR_PROMISC``
  membership on the socket, which the kernel drops together with the socket.
* **Windows and macOS**: a libpcap/Npcap/WinPcap capture handle in promiscuous
  mode with immediate delivery.

No BPF filter is installed. Every frame on the interface is read by ap51-flash
and dispatched by its ethernet source address. Frames with a broadcast source
address are dropped. IPv4 frames addressed to the ethernet broadcast address
are dropped as well. All other ethertypes than ARP (``0x0806``) and IPv4
(``0x0800``) are ignored.

When no frame arrives for 250 ms, a maintenance tick runs. The tick sends the
periodic probe frames described below (ARP probes for Ubiquiti devices, TFTP
write request retries, TCP SYN retries) and checks timers.

Because the host kernel also sees the device's frames, ap51-flash works best on
an interface without an IP configuration in the device's subnet and without a
TFTP server listening on the host. Otherwise the host kernel may answer the
same requests with conflicting data.


Phase 1: Detection
==================

Detection is based purely on ARP. Each supported router type inspects every
ARP frame coming from a not yet identified MAC address. The first type that
accepts the frame wins. The following signatures exist:

.. list-table::
   :header-rows: 1
   :widths: 18 50 32

   * - Flash mode
     - ARP signature sent by the device
     - Devices
   * - **TFTP client**
     - ARP *request* whose *target IP* is the fixed address the boot loader
       wants to download from: ``192.168.100.8`` (Open Mesh, Plasma Cloud,
       Datto), ``192.168.99.8`` (Open Mesh MR500) or ``192.168.1.99`` (Zyxel).
       The *target hardware address* field, which is normally all zero in an
       ARP request, is abused by these boot loaders to carry a model string in
       ASCII (for example ``OM2P``, ``MR600``, ``PAX180``, ``A60``) or a
       fixed byte pattern. ap51-flash matches this field (with a per-model
       mask) to tell the models apart.
     - Open Mesh, Plasma Cloud, Datto, Zyxel
   * - **RedBoot**
     - A *gratuitous* ARP request, i.e. an ARP request where the sender IP
       equals the target IP. RedBoot announces its own address this way when
       its network interface comes up. A gratuitous ARP for ``192.168.1.20``
       is only accepted after it has been seen 5 times, because Ubiquiti
       devices use the same address in TFTP server mode.
     - Any RedBoot with networking (La Fonera, Meraki Mini, DIR-300, ...)
   * - **TFTP server**
     - ARP *reply* from ``192.168.1.20``. The device does not announce itself,
       so ap51-flash actively sends an ARP request for ``192.168.1.20`` from
       ``192.168.1.25`` to the broadcast MAC on every 250 ms tick. Only after
       20 replies have been received is the device accepted, to give RedBoot
       based Ubiquiti devices time to be detected first.
     - Ubiquiti (Bullet, NanoStation, Pico, RouterStation)
   * - **Netconsole**
     - ARP *request* from ``192.168.1.1`` for ``192.168.1.2`` whose sender MAC
       is ``00:03:7f:09:0b:ad`` and whose target MAC is all zero.
     - Alfa Network AP121F

When a device is detected, ap51-flash records:

* ``his_ip``: the sender IP of the ARP frame (the device address),
* ``our_ip``: the target IP of the ARP frame (the address ap51-flash will
  impersonate). For RedBoot the last octet is changed to ``1`` if the device
  uses ``.20`` and to ``20`` otherwise, because a gratuitous ARP carries the
  device's own address in both fields.
* ``our_mac``: the next free address from ``00:ba:be:ca:ff:00`` upwards.

If the ``-m`` option was given and the device MAC is not on the allowlist, or if
no image for this device type was passed on the command line, the device is
marked as *not to be flashed* and all its further traffic is ignored.

From now on ap51-flash answers, for this device only:

* every ARP request for ``our_ip`` with an ARP reply carrying ``our_mac``,
* every ICMP echo request to ``our_ip`` with an ICMP echo reply.

The device type decides which of the four flash modes is used.


Phase 3a: TFTP client mode (Open Mesh, Plasma Cloud, Datto, Zyxel)
==================================================================

In this mode the boot loader of the device is the TFTP *client* and ap51-flash
acts as the TFTP *server*. Nothing has to be triggered; the boot loader starts
downloading on its own after the ARP exchange.

Wire sequence::

   device                                   ap51-flash
     |  ARP who-has 192.168.100.8 (tha="OM2P")  |
     |----------------------------------------->|   detection
     |  ARP 192.168.100.8 is-at 00:ba:be:ca:ff:00
     |<-----------------------------------------|
     |  UDP sport=X dport=69  RRQ "fwupgrade.cfg" octet
     |----------------------------------------->|
     |  UDP sport=69 dport=X  DATA block 1 (<=512 bytes)
     |<-----------------------------------------|
     |  UDP sport=X dport=69  ACK block 1       |
     |----------------------------------------->|
     |            ... DATA n / ACK n ...        |
     |  UDP sport=X dport=69  RRQ "kernel" octet (file names from fwupgrade.cfg)
     |----------------------------------------->|
     |            ... DATA / ACK ...            |
     |  UDP sport=X dport=69  RRQ "rootfs" octet
     |----------------------------------------->|
     |            ... DATA / ACK ...            |
     |                                          |  device writes flash,
     |                                          |  ap51-flash waits a timer
     |                                          |  and reports completion

Details:

* ap51-flash only looks at UDP datagrams with destination port ``69``. It
  answers from source port ``69`` and keeps doing so for the data blocks, i.e.
  it does not move to a random transfer identifier port as `RFC 1350`_
  section 4 describes. Clients that insist on the server changing its port
  are not supported.
* Data blocks are 512 bytes; no TFTP options (block size, transfer size) are
  negotiated. The transfer ends with a block shorter than 512 bytes.
* Retransmission: if an ACK repeats a block number ap51-flash already saw, the
  following block is sent again. An ACK for a block that was never sent is
  reported and the last acknowledged block is resent.
* The IP header has TTL 50 and no fragmentation. UDP checksums are filled in.
* **File names.** For the *combined ext image* (``CE`` header) used by Open
  Mesh, Plasma Cloud and Datto the boot loader first asks for
  ``fwupgrade.cfg`` and optionally ``fwupgrade.cfg.sig``. ap51-flash maps these
  to the ``fwupgrade.cfg-<model>`` and ``fwupgrade.cfg-<model>.sig`` entries of
  the image, so one image file can carry configurations for several models.
  The boot loader then requests the files named in the ``filename=`` lines
  of ``fwupgrade.cfg`` (typically a kernel and a root file system), and
  ap51-flash serves them from the matching entries of the CE container. For a
  plain *u-boot image* (Open Mesh MR500) the requested name is ``mr500.bin``
  or ``firmware.bin``; for a *Zyxel image* it is ``ras.bin``.
* **Completion.** ap51-flash sums the payload bytes of all files except the
  ``fwupgrade.cfg*`` files. When the sum reaches the total size the image
  header (or the ``fwupgrade.cfg`` of this model) announced, the transfer is
  complete and the message ``image successfully transmitted - writing image to
  flash`` is printed. The boot loader gives no feedback over the wire while it
  writes flash, so ap51-flash estimates: 10 seconds plus 1 second per 64 KiB
  transferred (45 seconds plus 1 second per 64 KiB for the MR500). After that
  it prints ``flash complete. Device ready to unplug``.


Phase 3b: TFTP server mode (Ubiquiti)
=====================================

Older Ubiquiti devices run a TFTP *server* in their boot loader at
``192.168.1.20`` when the reset button is held during power-on. Here
ap51-flash is the TFTP *client* and pushes the image with a write request.

Wire sequence::

   ap51-flash                               device
     |  ARP who-has 192.168.1.20 tell 192.168.1.25   (every 250 ms, broadcast)
     |----------------------------------------->|
     |  ARP 192.168.1.20 is-at <device MAC>     |
     |<-----------------------------------------|   (accepted after 20 replies)
     |  UDP sport=13337 dport=69  WRQ "flash_update" octet   (every 250 ms until ACK)
     |----------------------------------------->|
     |  UDP sport=69 dport=13337  ACK block 0   |
     |<-----------------------------------------|
     |  UDP sport=13337 dport=69  DATA block 1  |
     |----------------------------------------->|
     |  UDP sport=69 dport=13337  ACK block 1   |
     |<-----------------------------------------|
     |            ... DATA n / ACK n ...        |
     |            last DATA block < 512 bytes   |
     |----------------------------------------->|
     |  ACK                                     |
     |<-----------------------------------------|   image successfully transmitted
     |                                          |   device writes flash, reboots
     |  ARP (any) from device                   |
     |<-----------------------------------------|   flash complete

Details:

* The write request file name is literally ``"flash_update"`` including the
  double quotes. That is what the Ubiquiti boot loader expects.
* ap51-flash only processes replies that come from UDP source port ``69``.
* The complete *ubiquiti image* (``UBNT`` or ``OPEN`` magic) is sent as one
  file, padded to a multiple of 64 KiB.
* After the last block is acknowledged ap51-flash stops talking. The next ARP
  frame from the device's MAC address is taken as proof that it rebooted and
  the ``flash complete`` message is printed.


Phase 3c: RedBoot mode
======================

RedBoot_ is the eCos boot loader found on La Fonera, Meraki Mini, Ubiquiti
RouterStation, D-Link DIR-300 and others. It offers a command line over the
serial console and, on platforms with networking, over a telnet session on
`TCP port 9000`_. ap51-flash types the same commands a human would type into
that telnet session and lets RedBoot pull the kernel and root file system
with RedBoot's own TFTP client.

ap51-flash contains a minimal TCP implementation for this single connection:
a SYN with an MSS option, a three-way handshake, data segments with the PSH
flag, and retransmission of the last segment when RedBoot retransmits. There
is no window management beyond the fixed MSS and no FIN handling.

Wire sequence::

   ap51-flash                               RedBoot
     |  ARP who-has 192.168.1.20 tell 192.168.1.20 (gratuitous, from device)
     |<-----------------------------------------|   detection
     |  TCP sport=13337 dport=9000 SYN (MSS)    |   (every 250 ms until SYN/ACK)
     |----------------------------------------->|
     |  TCP SYN/ACK                             |
     |<-----------------------------------------|
     |  TCP ACK                                 |
     |----------------------------------------->|
     |  TCP data: RedBoot banner / boot script countdown
     |<-----------------------------------------|
     |  TCP data: 0x03 (Ctrl-C) - abort boot script
     |----------------------------------------->|
     |  TCP data: "RedBoot> " prompt            |
     |<-----------------------------------------|
     |  TCP data: "version\n"                   |
     |----------------------------------------->|
     |  TCP data: version text incl. "FLASH: 0x... - 0x..., N blocks of 0x... bytes each"
     |<-----------------------------------------|
     |  TCP data: "ip_addr -l 192.168.1.20/8 -h 192.168.1.1\n"
     |----------------------------------------->|
     |  TCP data: "load -r -b %{FREEMEMLO} -m tftp kernel\n"
     |----------------------------------------->|
     |  UDP sport=X dport=69  RRQ "kernel" octet   (RedBoot's TFTP client)
     |<-----------------------------------------|
     |            ... DATA / ACK (as in TFTP client mode) ...
     |  TCP data: "Raw file loaded ..." + prompt |
     |<-----------------------------------------|
     |  TCP data: "fis init\n"                  |
     |----------------------------------------->|
     |  TCP data: "About to initialize [format] FLASH image system - continue (y/n)?"
     |<-----------------------------------------|
     |  TCP data: "y\n"                         |
     |----------------------------------------->|
     |  TCP data: "fis create -e 0x80041000 -r 0x80041000 vmlinux.bin.l7\n"
     |----------------------------------------->|
     |  TCP data: "load -r -b %{FREEMEMLO} -m tftp rootfs\n"
     |----------------------------------------->|
     |  UDP  RRQ "rootfs" octet, DATA / ACK ... |
     |<-----------------------------------------|
     |  TCP data: "fis create -f 0x<addr> -l 0x<len> rootfs\n"
     |----------------------------------------->|
     |  TCP data: "fconfig -d boot_script_data\n"
     |----------------------------------------->|
     |  TCP data: "fis load -l vmlinux.bin.l7\n"
     |----------------------------------------->|
     |  TCP data: "exec\n\n"                    |
     |----------------------------------------->|
     |  TCP data: "y\n"   (confirm "Update RedBoot non-volatile configuration")
     |----------------------------------------->|
     |  TCP data: "reset\n"                     |
     |----------------------------------------->|
     |  ARP (any) from device after reboot      |
     |<-----------------------------------------|   flash complete

The command sequence step by step, with links to the RedBoot manual:

1. **Ctrl-C** is sent as soon as RedBoot sends its first bytes. This aborts
   the boot script countdown and gets a prompt. ap51-flash does not parse the
   prompt; every following command is sent when the reply to the previous one
   arrives.

2. `version`_ prints the RedBoot banner. ap51-flash parses the ``FLASH:`` line
   to find out whether the device has 8 MiB of flash. Every other device is
   treated as the 4 MiB default. The two layouts are:

   .. list-table::
      :header-rows: 1

      * - Flash
        - Usable size
        - Flash address of ``vmlinux.bin.l7``
        - Kernel load/entry address
        - Load buffer
      * - 4 MiB (default)
        - ``0x3A0000``
        - ``0xbfc30000``
        - ``0x80041000``
        - ``%{FREEMEMLO}``
      * - 8 MiB
        - ``0x7A0000``
        - ``0xa8030000``
        - ``0x80041000``
        - ``0x80041000`` (``%{FREEMEMLO}`` is broken on the Meraki Mini)

   If the image does not fit into the usable size, the session is aborted.

3. `ip_addr`_ ``-l <device>/8 -h <ap51-flash>`` sets RedBoot's local address
   and the default server address to the addresses chosen during detection.

4. `load`_ ``-r -b <buffer> -m tftp kernel`` makes RedBoot fetch the file
   ``kernel`` as raw binary via TFTP from the server address set in step 3.
   RedBoot is the TFTP client here and ap51-flash serves the ``kernel`` part
   of the *combined image* exactly as described for the TFTP client mode above. ap51-flash
   checks that the whole kernel was transferred before continuing.

5. `fis init`_ (re)creates the flash partition table, answered with ``y``.

6. `fis create`_ ``-e 0x80041000 -r 0x80041000 vmlinux.bin.l7`` writes the
   just loaded kernel into flash as partition ``vmlinux.bin.l7``. Length and
   data address default to the previously loaded file.

7. `load`_ ``-r -b <buffer> -m tftp rootfs`` fetches the ``rootfs`` part of the
   combined image the same way as the kernel.

8. `fis create`_ ``-f <flash_addr + kernel size> -l <usable size - kernel
   size> rootfs`` writes the root file system directly after the kernel,
   occupying the rest of the usable flash.

9. `fconfig`_ ``-d boot_script_data`` opens the boot script for editing in
   dumb terminal mode. The script lines `fis load`_ ``-l vmlinux.bin.l7`` and
   `exec`_ are entered, followed by an empty line to end the script and
   ``y`` to confirm writing the configuration to flash. See
   `Persistent State Flash-based Configuration and Control`_.

10. `reset`_ reboots the device. ap51-flash prints ``flash complete`` when it
    sees the first ARP frame from the device after the reset.

Kernel sizes are rounded up to 64 KiB flash pages. The *combined image*
(``CI`` header) format is ``CI<kernel size hex><rootfs size hex>`` followed by
64 KiB of header padding, the kernel and the root file system.


Phase 3d: Netconsole mode (Alfa Network AP121F)
===============================================

The U-Boot of the AP121F exposes its console over UDP (U-Boot *netconsole*,
port ``6666`` on both ends) and ships a ``fw_upg`` environment script that
downloads ``firmware.bin`` with TFTP and writes it to flash.

Wire sequence::

   device                                   ap51-flash
     |  ARP who-has 192.168.1.2 tell 192.168.1.1 (sha=00:03:7f:09:0b:ad)
     |----------------------------------------->|   detection
     |  ARP 192.168.1.2 is-at 00:ba:be:ca:ff:00 |
     |<-----------------------------------------|
     |  UDP sport=6666 dport=6666  "u-boot> "   |
     |----------------------------------------->|
     |  UDP sport=6666 dport=6666  "run fw_upg; reset\n"
     |<-----------------------------------------|
     |  UDP sport=X dport=69  RRQ "firmware.bin" octet
     |----------------------------------------->|
     |            ... DATA / ACK (as in TFTP client mode) ...
     |  UDP sport=6666 dport=6666  console output ... "DONE!"
     |----------------------------------------->|   flash complete, device resets

ap51-flash waits for a netconsole datagram starting with ``u-boot>``
before sending the command, serves the *u-boot image* (``0x27051956`` magic) as
``firmware.bin``, and declares success when a netconsole datagram starting
with ``DONE!`` arrives.


Addresses and ports at a glance
===============================

.. list-table::
   :header-rows: 1
   :widths: 20 22 22 36

   * - Flash mode
     - Device address
     - ap51-flash address
     - Ports
   * - TFTP client (Open Mesh, Plasma Cloud, Datto)
     - sender IP of the ARP request
     - ``192.168.100.8``
     - device ephemeral -> UDP 69; answers from UDP 69
   * - TFTP client (Open Mesh MR500)
     - sender IP of the ARP request
     - ``192.168.99.8``
     - as above
   * - TFTP client (Zyxel)
     - sender IP of the ARP request
     - ``192.168.1.99``
     - as above
   * - TFTP server (Ubiquiti)
     - ``192.168.1.20``
     - ``192.168.1.25``
     - UDP 13337 -> UDP 69; device answers from UDP 69
   * - RedBoot
     - gratuitous ARP address, e.g. ``192.168.1.20``
     - same subnet, last octet ``1`` (or ``20`` if the device uses something
       else)
     - TCP 13337 -> TCP 9000 (telnet); RedBoot TFTP client -> UDP 69
   * - Netconsole (AP121F)
     - ``192.168.1.1``
     - ``192.168.1.2``
     - UDP 6666 <-> UDP 6666; U-Boot TFTP client -> UDP 69

ap51-flash MAC addresses are always ``00:ba:be:ca:ff:00`` to
``00:ba:be:ca:ff:ff`` (one per detected device, in order of detection).


Image containers and the files served from them
===============================================

ap51-flash never serves the image file given on the command line as-is. It
parses the container header and serves the parts under the names the boot
loaders ask for.

.. list-table::
   :header-rows: 1
   :widths: 18 22 60

   * - Container
     - Magic
     - Files visible over TFTP
   * - combined image (``CI``)
     - ``CI`` + 2 x 8 hex digits
     - ``kernel``, ``rootfs`` (RedBoot mode)
   * - combined ext image (``CE``)
     - ``CE`` (old) or ``CE01`` (versioned), model list, file table
     - ``fwupgrade.cfg`` and ``fwupgrade.cfg.sig`` (mapped to the per-model
       entries), plus every file named in the container (kernel, rootfs, ...)
   * - u-boot image
     - ``0x27 0x05 0x19 0x56``
     - ``mr500.bin``, ``firmware.bin`` (whole file)
   * - ubiquiti image
     - ``UBNT`` or ``OPEN``
     - pushed as ``"flash_update"`` (whole file)
   * - Zyxel image
     - 64 KiB header with model and sizes
     - ``ras.bin`` (whole file)

Images can also be compiled into the binary (``EMBED_CI=...``,
``EMBED_CE=...`` and so on, see the ``Makefile``). An embedded image is served
exactly like one given on the command line.


Watching it yourself
====================

Everything described here is visible with a packet capture on the same
interface. Start the capture before powering on the device::

   tcpdump -i eth0 -n -e 'arp or icmp or udp port 69 or udp port 6666 or tcp port 9000'

Building ap51-flash with ``make CPPFLAGS=-DDEBUG`` prints every ARP frame
that is considered during detection.


.. _RFC 1350: https://www.rfc-editor.org/rfc/rfc1350
.. _RedBoot: https://ecos.sourceware.org/docs-latest/redboot/redboot-guide.html
.. _TCP port 9000: https://ecos.sourceware.org/docs-latest/redboot/user-interface.html
.. _version: https://ecos.sourceware.org/docs-latest/redboot/version-command.html
.. _ip_addr: https://ecos.sourceware.org/docs-latest/redboot/ip-address-command.html
.. _load: https://ecos.sourceware.org/docs-latest/redboot/download-command.html
.. _fis init: https://ecos.sourceware.org/docs-latest/redboot/fis-init-command.html
.. _fis create: https://ecos.sourceware.org/docs-latest/redboot/fis-create-command.html
.. _fis load: https://ecos.sourceware.org/docs-latest/redboot/fis-load-command.html
.. _fconfig: https://ecos.sourceware.org/docs-latest/redboot/persistent-state-flash.html
.. _Persistent State Flash-based Configuration and Control: https://ecos.sourceware.org/docs-latest/redboot/persistent-state-flash.html
.. _exec: https://ecos.sourceware.org/docs-latest/redboot/exec-command.html
.. _reset: https://ecos.sourceware.org/docs-latest/redboot/reset-command.html
