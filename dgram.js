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

var net = require('net');
var util = require('util');

var EtherStream = require('ether-stream');
var IpStream = require('ip-stream');
var ip = require('ip');
var MockDgram = require('mock-dgram');
var PcapStream = require('pcap-stream');
var SelectStream = require('select-stream');
var UdpStream = require('udp-stream');

util.inherits(PcapDgram, MockDgram);

function PcapDgram(pcapSource, address, opts) {
  var self = (this instanceof PcapDgram)
           ? this
           : Object.create(PcapDgram.prototype);

  if (!net.isIPv4(address)) {
    throw(new Error('PcapDgram requires a valid IPv4 address; [' +
                    address + '] is invalid.'));
  }

  opts = opts || {};
  opts.address = address;

  MockDgram.call(self, opts);

  self._netmask = net.isIPv4(opts.netmask) ? opts.netmask : '255.255.255.255';
  self._broadcast = ip.or(ip.not(self._netmask), self._address);

  new PcapStream(pcapSource).pipe(new EtherStream())
                            .pipe(new IpStream())
                            .pipe(new UdpStream())
                            .pipe(new SelectStream(self._select.bind(self)))
                            .pipe(self.input);

  return self;
}

PcapDgram.prototype._select = function(msg) {
  // ignore packets not destined for configured IP/port
  if (!this._matchAddr(msg.ip.dst) || (this._port &&
                                       msg.udp.dstPort !== this._port)) {
    return false;
  }

  // auto-detect configured port if not set
  if (!this._port) {
    this._port = msg.udp.dstPort;
  }

  return true;
}

PcapDgram.prototype._matchAddr = function(address) {
  return address === this._address ||
         address === this._broadcast ||
         address === '255.255.255.255';
};
