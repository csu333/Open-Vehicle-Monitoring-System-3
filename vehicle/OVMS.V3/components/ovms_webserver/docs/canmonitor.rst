===========
CAN Monitor
===========

The CAN Monitor is a **live reverse-engineering aid** accessible under
**Tools → CAN Monitor** (``/canmonitor``).  It captures CAN bus frames
via the built-in RE (reverse-engineering) framework, automatically
reassembles ISO 15765-2 multi-frame messages, and displays a live
updating table of every unique (ID, Type, PID) combination seen on the
bus.

Use it to discover which CAN IDs carry data you are interested in,
to perform OBDII/UDS PID scans to find supported PIDs on an ECU, and
to transmit raw CAN frames for diagnostic testing.

.. note::
   The CAN bus you want to monitor must be started before using this
   tool.  Issue ``can start <bus> active`` (or ``can start <bus>
   passive`` for listen-only) from the shell, or use the **Vehicle**
   configuration page to start the buses at boot.


-------------------
Frame Capture Table
-------------------

Click **RE Start** in the toolbar to start the RE framework and begin
receiving frames.  The table updates automatically every 500 ms via a
dedicated WebSocket connection.

Each row represents one unique combination of CAN ID, service type byte,
and PID.  The columns are:

:Bus:       CAN bus the frame arrived on (``can1`` – ``can5``).
:ID:        CAN message identifier.  Standard (11-bit) IDs are shown as
            three hex digits; extended (29-bit) IDs as eight hex digits.
:Type:      Service type byte (first payload byte), shown as two hex
            digits.  ``--`` if not applicable (e.g. raw non-UDS frames).
:PID:       Parameter identifier, shown as two hex digits (8-bit) or
            four hex digits (16-bit for UDS service ``22``/``62``).
            ``--`` if not applicable.
:Hex data:  Payload bytes after the type and PID bytes, space-separated
            hex.  Click a row to view the per-frame history of up to ten
            previous values.  Multi-frame (reassembled) payloads are
            highlighted in yellow and may be many bytes long.
:Int64 LE:  The first ≤ 8 data bytes interpreted as a little-endian
            signed 64-bit integer.  Trailing padding bytes (``0x00``,
            ``0x55``, ``0xAA``) are stripped before the conversion.
:Int64 BE:  Same data interpreted as big-endian.
:Count:     Number of updates received for this row since the last
            clear.
:Rate:      Estimated update rate in frames/s.  Hover over the cell to
            see a sparkline chart of the rate history.
:Label:     Free-text annotation you can type directly into the cell.
            Labels are preserved across table refreshes.
:Formula:   A JavaScript expression evaluated against the data bytes to
            produce a decoded value.  Use ``d[0]``, ``d[1]`` … to
            reference individual bytes (``d`` is a ``Uint8Array``).
            Example: ``((d[0] << 8 | d[1]) * 0.1).toFixed(1) + ' V'``.

Columns marked *LE*, *BE*, *Rate*, *Label*, and *Formula* are hidden on
narrow screens by default.  Use the **More cols** button in the
panel heading to reveal them.


--------------
Freeze / Diffs
--------------

Click **Freeze** to take a snapshot of the current hex data for every
row.  While frozen, bytes that have changed relative to the snapshot are
highlighted in red, making it easy to see which fields respond to a
specific vehicle action.  Click **Unfreeze** (the same button, now
labelled differently) to return to normal live updating.


-------------------
OBDII / UDS Queries
-------------------

The *OBDII PID Query* panel sends a sequential series of OBD/UDS poll
requests and populates the capture table with any responses.

Enter all values in hexadecimal (case insensitive).

:Bus:       CAN bus to send requests on (``can1`` – ``can5``).  The bus
            must be in **active** mode.
:TX ID:     CAN ID for outgoing request frames.  Use ``7DF`` for the
            standard OBD broadcast address, or the specific ECU request
            ID (e.g. ``7E0``).
:Mode:      OBD service / UDS poll type byte (optional).  Leave blank to
            use the default (``01`` for OBD-II Mode 1, ``22`` for UDS
            ReadDataByIdentifier, etc.).
:PID range: First and last PID to scan, inclusive.  8-bit PIDs must
            stay in the range ``00``–``FF``; 16-bit UDS PIDs in the
            range ``0000``–``FFFF``.
:Resp:      Expected ECU response CAN ID or range (optional).  Leave
            blank to accept any response.  Default ECU response IDs are
            typically TX ID + 8 (e.g. ``7E8`` for a ``7E0`` request).
            Use a range like ``7E8``–``7EF`` to accept any ECU on the
            bus.
:Timeout:   Time in seconds to wait for a response before moving to the
            next PID (1–10 s, default 3 s).

Click **Start Query** to begin scanning.  The status label shows the
current PID being queried.  Click **Stop Query** to abort early.  Only
rows with a non-zero response payload are shown in the table.

The **History** button (clock icon) shows a log of previous queries so
you can re-run a useful configuration without re-entering the values.

.. warning::
   The scanner sends poll requests to ECUs over the CAN bus.  Only
   read-oriented poll types (e.g. ``01``, ``22``) should normally be
   used.  Using write or control poll types may alter ECU state.  To
   avoid conflicts with vehicle-specific poll schedules, run scans
   with the vehicle module set to **NONE** (``vehicle module NONE``).
   The scanner does not issue UDS session or tester-presence messages;
   use ``re obdii tester`` if your ECU requires them.


------
CAN TX
------

The *CAN TX* panel transmits a single raw CAN frame.

:Bus:     Target bus (must be in **active** mode).
:CAN ID:  Frame identifier in hex.  IDs above ``7FF`` are sent as
          extended (29-bit) frames; ``7FF`` and below are sent as
          standard (11-bit) frames.
:Data:    Up to 8 payload bytes in hex (spaces are ignored).  Example:
          ``02 10 03 00 00 00 00 00``.

Click **Send**.  The status label confirms success or reports an error.
The **History** button (clock icon) recalls previously sent frames.


------------------
Export and Logging
------------------

**Export CSV**
  Downloads the current table contents as a CSV file with columns for
  Bus, ID, Type, PID, Hex data, Int64 LE, Int64 BE, Count, Rate, Label,
  and Formula.  Only the rows currently visible in the table are exported.

**CRTD** (⏺ button)
  Starts a continuous log of every frame update in CRTD format, stored
  in the browser's local IndexedDB.  The log status indicator shows the
  record count.  Click again to stop and download the file.  Clicking
  **Clear** while logging is active stops the log and clears the
  IndexedDB store.


-------------------
DBC Signal Decoding
-------------------

If DBC files have been loaded on the module (``dbc load`` command), the
monitor fetches their signal definitions on connect.  Decoded signal
values are shown automatically in the *Formula* column for any row whose
CAN ID matches a message defined in the loaded DBC files.  Manually
entered formulas take precedence over DBC-derived ones.


---------
RE Filter
---------

By default **RE Start** captures all frames on all active buses.  For
busy buses this can quickly fill the 250-row table limit, making it
harder to find relevant data.  You can restrict capture to specific IDs
using the RE filter syntax accepted by the ``re start`` command.  The
filter is passed through the WebSocket ``start`` action; invoke ``re
start`` directly from the shell if you need a filter:

.. code-block:: none

   re start 1:7E0-7EF

This limits capture to CAN IDs 7E0 through 7EF on bus 1.  See
``re help`` for the full filter syntax.


-----------
HTTP/Script
-----------

A legacy JSON endpoint is available for scripting or CLI use:

- ``GET  /api/canmonitor`` — returns the current frame snapshot as
  JSON: ``{"running": bool, "scanning": bool, "frames": [...]}``.
- ``POST /api/canmonitor`` — accepts ``action=start|stop|clear|query|
  stopquery|cantx`` with the same parameters as the WebSocket commands.

Both endpoints require cookie authentication when a module password is
configured.
