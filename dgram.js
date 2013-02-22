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
if (!Readable) {
  Readable = require('readable-stream');
}
var EventEmitter = require('events').EventEmitter;
var net = require('net');
var util = require('util');

var EtherStream = require('ether-stream');
var IpHeader = require('ip-header');
var ip = require('ip');
var PcapStream = require('pcap-stream');

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

  self._reading = false;

  self._pstream = new PcapStream(pcapSource);
  self._estream = new EtherStream();
  self._estream.on('end', self._onEnd.bind(self));
  self._estream.on('error', self.emit.bind(self, 'error'));

  self._pstream.pipe(self._estream);

  if (!opts.paused) {
    self.resume();
  }

  return self;
}

PcapDgram.prototype.pause = function() {
  this._reading = false;
};

PcapDgram.prototype.resume = function() {
  var self = this;
  if (!self._reading) {
    self._reading = true;
    process.nextTick(function() {
      if (self._needListening) {
        self._needListening = false;
        self.emit('listening');
      }
      self._flow();
    });
  }
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
  if (!this._reading) {
    return;
  }

  var msg = this._estream.read();
  if (!msg) {
    this._estream.once('readable', this._flow.bind(this));
    return;
  }

  this._onData(msg);

  return this._flow();
};

PcapDgram.prototype._onData = function(msg) {
  // Only consider IP packets.  Ignore all others
  if (msg.ether.type !== 'ip') {
    return;
  }

  try {
    var iph = new IpHeader(msg.data);

    // Only consider UDP packets without IP fragmentation
    if (iph.protocol !== 'udp' || iph.flags.mf || iph.offset) {
      return;
    }

    var udp = this._parseUDP(msg.data, iph.length);

    // ignore packets not destined for configured IP/port
    if (!this._matchAddr(iph.dst) || (this._port &&
                                      udp.dstPort !== this._port)) {
      return;
    }

    // auto-detect configured port if not set
    if (!this._port) {
      this._port = udp.dstPort;
    }

    var rinfo = {address: iph.src, port: udp.srcPort, size: udp.data.length};
    this.emit('message', udp.data, rinfo);

  } catch (error) {
    // silently ignore packets we can't parse
  }
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

PcapDgram.prototype._parseUDP = function(buf, offset) {
  offset = ~~offset;

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
