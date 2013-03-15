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

var PcapDgram = require('../dgram');

var path = require('path');

var FILE = path.join(__dirname, 'data', 'netbios-ns-b-register-winxp.pcap');

module.exports.message = function(test) {
  test.expect(4);

  var pdgram = new PcapDgram(FILE, '192.168.207.2');

  pdgram.on('message', function(msg, rinfo) {
    // assert values from inspecting pcap with tshark
    test.equal(68, msg.length);
    test.equal(msg.length, rinfo.size);
    test.equal('192.168.207.128', rinfo.address);
    test.equal(137, rinfo.port);
  });

  pdgram.on('close', function() {
    test.done();
  });
};

module.exports.output = function(test) {
  test.expect(4);

  var pdgram = new PcapDgram(FILE, '192.168.207.2');

  var hello = new Buffer('Hello world!');
  var remoteAddr = '192.168.207.128';
  var remotePort = 137;

  pdgram.output.on('readable', function() {
    var msg = pdgram.output.read();
    test.equal(hello.toString(), msg.data.toString());
    test.equal(remotePort, msg.udp.dstPort);
    test.equal(remoteAddr, msg.ip.dst);
  });

  pdgram.on('message', function(msg, rinfo) {
    pdgram.send(hello, 0, hello.length, remotePort, remoteAddr, function(error) {
      test.equal(null, error);
    });
  });

  pdgram.on('close', function() {
    test.done();
  });
};
