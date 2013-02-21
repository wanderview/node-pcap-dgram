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

module.exports.example = function(test) {
  test.expect(8);

  var hello = new Buffer('Hello world!');
  var remoteAddr = '192.168.207.128';
  var remotePort = 137;

  // Create a dgram socket using a netbios name service pcap file
  var file = path.join(__dirname, 'data', 'netbios-ns-b-register-winxp.pcap');
  var pdgram = new PcapDgram(file, '192.168.207.2', {paused: true});

  // When we receive the netbios name service packet, validate it
  pdgram.on('message', function(msg, rinfo) {
    // assert values from inspecting pcap with tshark
    test.equal(68, msg.length);
    test.equal(msg.length, rinfo.size);
    test.equal(remoteAddr, rinfo.address);
    test.equal(remotePort, rinfo.port);

    // Simulate sending a response back
    pdgram.send(hello, 0, hello.length, rinfo.port, rinfo.address, function(error) {
      test.equal(null, error);
    });
  });

  // Validate the response was sent
  pdgram.on('output', function(msg, port, address) {
    test.equal(hello.toString(), msg.toString());
    test.equal(remotePort, port);
    test.equal(remoteAddr, address);
  });

  pdgram.on('close', function() {
    test.done();
  });

  // because we constructor pdgram with {paused:true} we must explicitly start
  pdgram.resume();
};
