// Copyright (c) 2013, Benjamin J. Kelly ("Author")
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

'use strict';

module.exports = PcapDgram;

var stream = require('stream');
var Readable = stream.Readable;
// NOTE: we cannot use readable-stream for compat because it lacks objectMode
var EventEmitter = require('events').EventEmitter;
var net = require('net');
var util = require('util');

var ip = require('ip');
var pcap = require('pcap-parser');

util.inherits(PcapDgram, EventEmitter);

function PcapDgram(pcapSource, address, opts) {
  var self = (this instanceof PcapDgram)
           ? this
           : Object.create(PcapDgram.prototype);

  opts = opts || {};

  EventEmitter.call(self, opts);

  if (!net.isIPv4(address)) {
    throw(new Error('PcapDgram requires a valid IPv4 address; [' +
                    address + '] is invalid.'));
  }

  self._address = address;
  self._port = ~~opts.port;
  self._netmask = net.isIPv4(opts.netmask) ? opts.netmask : '255.255.255.255';
  self._broadcast = ip.or(ip.not(self._netmask), self._address);

  self._stream = new Readable({objectMode: true});
  self._stream.on('end', self._onEnd.bind(self));

  self._reading = true;

  self._parser = pcap.parse(pcapSource);
  self._parser.on('end', self._stream.push.bind(self._stream, null));
  self._parser.on('error', self.emit.bind(self, 'error'));
  self._parser.on('packet', function(packet) {
    var res = self._stream.push(packet);
    if (!res) {
      self._pause();
    }
  });

  self._stream._read = self._resume.bind(self);

  return self;
}

PcapDgram.prototype.start = function() {
  var self = this;
  process.nextTick(function() {
    self.emit('listening');
    self._flow();
  });
};

PcapDgram.prototype.send = function(buf, offset, length, port, address, callback) {
  var msg = buf.slice(offset, offset + length);
  this.emit('output', msg, port, address);
  if (typeof callback === 'function') {
    callback(null, msg.length);
  }
};

PcapDgram.prototype.close = function() {
  this._onEnd();
};

PcapDgram.prototype.address = function() {
  return { address: this._address, family: 'IPv4', port: this._port };
};

PcapDgram.prototype._flow = function() {
  var packet = this._stream.read();
  if (!packet) {
    this._stream.once('readable', this._flow.bind(this));
    return;
  }
  this._onData(packet);
};

PcapDgram.prototype._onData = function(packet) {
  var payload = packet.data;

  var ether = this._parseEthernet(payload);

  // Only consider IP packets.  Ignore all others
  if (ether.type !== 0x0800) {
    return;
  }

  var iph = this._parseIP(ether.data);

  // Only consider UDP packets without IP fragmentation
  if (!iph || iph.protocol !== 0x11 || iph.mf || iph.offset) {
    return;
  }

  var udp = this._parseUDP(iph.data);

  // ignore packets not destined for configured IP/port
  if (!this._matchAddr(iph.dst) || (this._port && udp.dstPort !== this._port)) {
    return;
  }

  // auto-detect configured port if not set
  if (!this._port) {
    this._port = udp.dstPort;
  }

  var rinfo = {address: iph.src, port: udp.srcPort, size: udp.data.length};
  this.emit('message', udp.data, rinfo);
};

PcapDgram.prototype._onEnd = function() {
  // Prevent duplicate 'close' events by only allowing this function to be
  // called once.  This can happen when close() is called before the
  // pcap-parser runs to completion.
  this._onEnd = function() {};

  // Also, match dgram core behavior and throw if send is called after end
  this.send = function() {
    throw new Error('Not running');
  }

  this.emit('close');
};

PcapDgram.prototype._matchAddr = function(address) {
  return address === this._address ||
         address === this._broadcast ||
         address === '255.255.255.255';
};

PcapDgram.prototype._pause = function(address) {
  if (this._reading) {
    this._reading = false;
    this._parser.stream.pause();
  }
};

PcapDgram.prototype._resume = function(address) {
  if (!this._reading) {
    this._reading = true;
    this._parser.stream.resume();
  }
};

// TODO: move _parseEthernet to a separate module to shared with pcap-socket
PcapDgram.prototype._parseEthernet = function(buf) {
  var offset = 0;

  var dst = buf.slice(offset, offset + 6);
  offset += 6;

  var src = buf.slice(offset, offset + 6);
  offset += 6;

  var type = buf.readUInt16BE(offset);
  offset += 2;

  var data = buf.slice(offset);

  return { dst: dst, src: src, type: type, data: data };
};

// TODO: move _parseIP to a separate module to shared with pcap-socket
PcapDgram.prototype._parseIP = function(buf) {
  var offset = 0;

  var tmp = buf.readUInt8(offset);
  offset += 1;

  var version = (tmp & 0xf0) >> 4;
  if (version != 4) {
    return null;
  }

  var headerLength = (tmp & 0x0f) * 4;

  // skip DSCP and ECN fields
  offset += 1;

  var totalLength = buf.readUInt16BE(offset);
  offset += 2;

  var id = buf.readUInt16BE(offset);
  offset += 2;

  tmp = buf.readUInt16BE(offset);
  offset += 2;

  var flags = (tmp & 0xe000) >> 13;
  var fragmentOffset = tmp & 0x1fff;

  var df = !!(flags & 0x2);
  var mf = !!(flags & 0x4);

  var ttl = buf.readUInt8(offset);
  offset += 1;

  var protocol = buf.readUInt8(offset);
  offset += 1;

  var checksum = buf.readUInt16BE(offset);
  offset += 2;

  var src = ip.toString(buf.slice(offset, offset + 4));
  offset += 4;

  var dst = ip.toString(buf.slice(offset, offset + 4));
  offset += 4;

  var data = buf.slice(headerLength);

  return { flags: {df: df, mf: mf}, id: id, offset: fragmentOffset, ttl: ttl,
           protocol: protocol, src: src, dst: dst, data: data };
};

PcapDgram.prototype._parseUDP = function(buf) {
  var offset = 0;

  var srcPort = buf.readUInt16BE(offset);
  offset += 2;

  var dstPort = buf.readUInt16BE(offset);
  offset += 2;

  // length in bytes of header + data
  var length = buf.readUInt16BE(offset);
  offset += 2;

  var checksum = buf.readUInt16BE(offset);
  offset += 2;

  var data = buf.slice(8, length);

  return { srcPort: srcPort, dstPort: dstPort, length: length,
           checksum: checksum, data: data };
};

// Compatibility stubs
PcapDgram.prototype.bind = function(port, address) {};
PcapDgram.prototype.setBroadcast = function(flag) {};
PcapDgram.prototype.setTTL = function(ttl) {};
PcapDgram.prototype.setMulticastTTL = function(ttl) {};
PcapDgram.prototype.setMulticastLoopback = function(flag) {};
PcapDgram.prototype.addMembership = function(mcAddress, mcInterface) {};
PcapDgram.prototype.dropMembership = function(mcAddress, mcInterface) {};
PcapDgram.prototype.unref = function() {};
PcapDgram.prototype.ref = function() {};
