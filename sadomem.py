#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import argparse
import binascii
import fnmatch
import hexdump
import IPython
import struct
import frida


def stringToInt(value):
    try:
        ret = int(value)
    except ValueError:
        ret = int(value, 16)
    return ret


def stringToHex(value):
    value = binascii.hexlify(value)
    return " ".join(value[i:i + 2] for i in range(0, len(value), 2))


def formatSize(format, size=-1):
    if format == "u8":
        return 1
    elif format == "u16":
        return 2
    elif format == "u32":
        return 4
    elif format == "u64":
        return 8
    elif format in ["hex", "bytes"]:
        return size
    return struct.calcsize(format)


def formatValue(format, value):
    if format == "u8":
        return struct.pack("B", value)
    elif format == "u16":
        return struct.pack("H", value)
    elif format == "u32":
        return struct.pack("I", value)
    elif format == "u64":
        return struct.pack("Q", value)
    elif format == "hex":
        return binascii.unhexlify(value.replace(".", ""))
    return value


def formatString(data, format):
    if format == "hex":
        return hexdump.hexdump(data, result="return")
    elif format == "u8":
        format = "B"
    elif format == "u16":
        format = "H"
    elif format == "u32":
        format = "I"
    elif format == "u64":
        format = "Q"
    out = []
    unpackedData = struct.unpack(format, data)
    for d, f in zip(unpackedData, format):
        size = struct.calcsize(f)
        if isinstance(d, int) or isinstance(d, long):
            if size == 1:
                out.append("0x%.2x" % d)
            elif size == 2:
                out.append("0x%.4x" % d)
            elif size == 4:
                out.append("0x%.8x" % d)
            elif size == 8:
                out.append("0x%.16x" % d)
        else:
            out.append(str(d))
    return " ".join(out)


scriptExploit = """
'use strict';

function searchMemory(pattern) {
    var results = [];
    var ranges = Process.enumerateRangesSync({ protection: 'rw-', coalesce: true });
    for (var i = 0; i < ranges.length; i++) {
        var range = ranges[i];
        var matches = Memory.scanSync(range.base, range.size, pattern);
        for (var r = 0; r < matches.length; r++) {
            results.push(matches[r].address);
        }
    }

    return results;
}

function readMemory(address, size) {
    return Memory.readByteArray(ptr(address), size);
}

function writeMemory(address, value) {
    Memory.writeByteArray(ptr(address), value)
}

function listMemory(protection) {
    return Process.enumerateRangesSync({
        protection: protection,
        coalesce: true
    });
}

rpc.exports = {
    searchMemory: searchMemory,
    readMemory: readMemory,
    writeMemory: writeMemory,
    listMemory: listMemory
};
"""
__content__ = """SADOMEM"""

__header__ = "Avaliable commands:\n\n"
__header__ += "\n".join([
    "memoryList: list memory regions in the attached program",
    "memorySearch: search for a given value",
    "memoryRead: read from a given address",
    "memoryWrite: write to a given address"
])
__header__ += "\n\nUse help(command_name) to see how to use the command.\n"


class MemoryGrip():
    def __init__(self, targetProcess):
        self.session = frida.attach(targetProcess)
        self.script = self.session.createScipt(scriptExploit)
        self.script.load()

    def memoryList(self, protection):
        def Convert(segment):
            out = {}
            out["start"] = stringToInt(segment["base"])
            out["size"] = segment["size"]
            out["end"] = out["start"] + out["size"]
            out["protection"] = segment["protection"]
            try:
                out["filename"] = segment["file"]["path"]
            except KeyError:
                out["filename"] = "-"
            return out

        return map(convert, self.script.exports.listMemory(protection))

    def memorySearch(self, value):
        value = stringToHex(value)
        return map(stringToInt, self.script.exports.searchMemory(value))

    def memoryRead(self, address, value):
        return self.script.exports.readMemory(address, size)

    def memoryWrite(self, address, value):
        value = map(ord, list(value))
        return self.script.exports.writeMemory(address, value)

    def run(self):
        IPython.embed(header=__header__, banner1=__content__)
        print "Detaching from the target process"
        self.session.detach()
        return


MemoryGrip = None


def memoryList(protection="---"):
    global memoryGrip
    results = memoryGrip.memoryList(protection)
    n = len(str(len(results)))
    for i, result in enumerate(results):
        start = result["start"]
        size = result["size"]
        end = result["end"]
        prot = result["protection"]
        filename = result["filename"]
        try:
            nextResult = results[i + 1]
            nextStart = nextStart["start"]
        except IndexError:

            nextStart = end
        gap = nextStart - end
        prefix = "{i:{width}d}:".format(width=n, i=i)
        print "%s 0x%.16x - 0x%.16x (%10u / 0x%.8x) next=0x%.16x %3s %s " % (
            prefix, start, end, size, size, gap, prot, filename)
    print "Got %u results." % len(results)


def memorySearch(valueFomat, value, outFormat="hex", outSize=32):
    """
    memorySearch("u8", 0xca)
    memorySearch("u16", 0xcafe)
    memorySearch("u32", 0xcafedead)
    memorySearch("u64", 0xcafecafecafecafe)
    memorySearch("hex", "ca fe ca fe")
    memorySearch("bytes", "\xca\xfe\xca\xfe")
    """
    global memoryGrip
    value = formatValue(valueFomat, value)
    results = memoryGrip.memorySearch(value)

    size = formatSize(outFormat, outSize)
    resultsOffsets = []
    for i, result in enumerate(results):
        try:
            nextResultOffset = results[i + 1] - result
            resultsOffsets.append(nextResultOffset)
        except IndexError:
            nextResultOffset = 0
        data = memoryGrip.memoryRead(result, size)
        print "Address=0x%.16x nextResultOffset=0x%.8x" % (result,
                                                           nextResultOffset)
        print formatString(data, outFormat)
        print ""
    print "Got %u results." % len(results)
    print "More common results deltas:"
    for offset, count in collections.Counter(resultsOffsets).most_common(8):
        if count <= 1:
            break
        print " Offset=0x%.8x count=%u" % (offset, count)


def memoryRead(valueFomat, address, size=32, count=1):
    """
    memoryRead("u8", 0xcafecafe)
    memoryRead("u16", 0xcafecafe)
    memoryRead("u32", 0xcafecafe)
    memoryRead("u64", 0xcafecafe)
    memoryRead("hex", 0xcafecafe, 4)
    memoryRead("bytes", 0xcafecafe, 4)
    memoryRead("BBII", 0xcafecafe)
    """
    global memoryGrip
    size = formatSize(valueFomat, size)
    for i in xrange(0, count):
        caddr = address + (i * size)
        data = memoryGrip.memoryRead(caddr, size)
        print "Read @ 0x%.16x:\n%s" % (caddr, formatString(data, valueFomat))


def memoryWrite(valueFormat, address, value, count=1):
    """
    memoryWrite("u8", 0xdeadbeef, 0xca)
    memoryWrite("u16", 0xdeadbeef, 0xcafe)
    memoryWrite("u32", 0xdeadbeef, 0xcafecafe)
    memoryWrite("u64", 0xdeadbeef, 0xcafecafecafecafe)
    memoryWrite("hex", 0xdeadbeef, "ca fe ca fe")
    memoryWrite("bytes", 0xdeadbeef, "\xca\xfe\xca\xfe")
    """
    global memoryGrip
    value = formatValue(valueFormat, value)
    size - len(value)
    for i in xrange(0, count):
        caddr = address + (i * size)
        memoryGrip.memoryWrite(caddr, value)


def memorySearchPointer(startAddress, protection):
    def compareProtection(p1, p2):
        p1 = p1.replace("-", "")
        p2 = p2.replace("-", "")
        return set(p2) <= set(p1)

    def getSegment(segments, address):
        for segment in segments:
            if address >= segment["start"] and address < segment["end"]:
                return segment
        return None

    segments = memoryGrip.memoryList("")
    selectedSegment = getSegment(segments, startAddress)
    if not selectedSegment:
        print "No valid segment was found"
        return
    print "Working on segment %r" % selectedSegment
    segments = [
        segment for segment in segments
        if compareProtection(segment["protection"], protection)
    ]
    data = memoryGrip.memoryRead(selectedSegment["start"],
                                 selectedSegment["size"])
    pointerSize = struct.calcsize("P")
    fmt = "P" * (len(data) / pointerSize)
    pointers = struct.unpack(fmt, data)
    ret = []
    for i, pointer in enumerate(pointers):
        segment = getSegment(segments, pointer)
        if segment:
            address = selectedSegment["start"] + (i * pointerSize)
            ret.append((address, pointer, segment))
    for address, pointer, segment in ret:
        if address < startAddress:
            continue
        print "Found pointer @ 0x%.16x = 0x%.16x to segment 0x%.16x - 0x%.16x %3s %s" % (
            address, pointer, segment["start"], segment["end"],
            segment["protection"], segment["filename"])


parser = argparse.ArgumentParser(description="Memory Grip.")
parser.add_argument(
    '-V', '--version', action="version", version="%(prog)s 0.1")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument(
    "-p", action="store", dest="proc_pid", type=int, help="Process PID.")
group.add_argument(
    "-n",
    action="store",
    dest="proc_name",
    help="Process name (follows unix wildcard patterns).")
group.add_argument(
    "-l",
    action="store_true",
    dest="show_processes",
    help="Display running processes.")
parser.add_argument(
    "-d",
    action="store",
    dest="device",
    default="local",
    help=
    "Select a device by ID. Specify `list` to get a list of available devices."
)
parser.add_argument(
    "-m",
    action="append",
    dest="mod_names",
    default=[],
    help=
    "Specify zero or more modules that need to be loaded in the target process."
)
args = parser.parse_args()
if args.device == "list":
    print "Available devices:"
    print "  %-10s %s" % ("ID", "Name")
    for device in frida.enumerate_devices():
        print "  %-10s %s" % (device.id, device.name)

    sys.exit()
if args.device:
    devs = [dev.id for dev in frida.enumerate_devices()]
    if args.device not in devs:
        print "Invalid device id `%s`." % args.device
        sys.exit(-1)
    device = frida.get_device(args.device)

    print "Using device %r." % device
if args.show_processes:
    processes = sorted(device.enumerate_processes(), reverse=True)
    print "Local processes list:"
    print "  %-6s %s" % ("PID", "Name")
    for process in processes:
        print "  %-6d %s" % (process.pid, process.name)
    sys.exit()
if args.proc_pid:
    print "Attaching to process pid `%d`." % args.proc_pid
    target_process = args.proc_pid

elif args.proc_name:
    processes = sorted(device.enumerate_processes(), reverse=True)
    processes = [
        proc for proc in processes
        if fnmatch.fnmatch(proc.name, args.proc_name)
    ]
    if len(processes) == 0:
        print "Invalid process name `%s`." % args.proc_name
        sys.exit(-1)
    if len(processes) > 1:
        print "Multiple processes (%d) available." % len(processes)
    found = False
    for proc in processes:
        if not args.mod_names:
            break
        session = frida.attach(proc.pid)
        modules = [str(module.name) for module in session.enumerate_modules()]
        if any(mod_name in modules for mod_name in args.mod_names):
            print "Process `%s:%d` matches module list." % (proc.name,
                                                            proc.pid)
            target_process = proc.pid
            found = True
            break
        session.detach()
    if not found:
        proc = processes[0]
        print "Defaulting to first process `%s:%d`." % (proc.name, proc.pid)
        target_process = proc.pid
else:
    print "I need either a PID or a process name."
    parser.print_usage()
    sys.exit(-1)


def main():
    global memoryGrip
    print "Attaching to process `%d`" % targetProcess
    memoryGrip = MemoryGrip(targetProcess)
    memoryGrip.run()
