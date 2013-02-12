# pcap-dgram

Mock UDP socket based on pcap file data.

[![Build Status](https://travis-ci.org/wanderview/node-pcap-dgram.png)](https://travis-ci.org/wanderview/node-pcap-dgram)

## Example

```javascript
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
  var pdgram = new PcapDgram(file, '192.168.207.2');

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

  pdgram.start();
};
```

## Limitations / TODO

* Currently only supports IPv4.
* Currently ignores all fragmented IP packets.

## Class PcapDgram

The PcapDgram class implements the same API as the [dgram.Socket][] class.
Data is delivered to the `'message'` event by reading data from a pcap
file.  Outgoing data is redirected to the `'output'` event so that it
can be validated for correctness.

### var pdgram = new PcapDgram(pcapSource, address, opts)

* `pcapSource` {String | Stream} If a String, pcapSource is interpreted as
  the name of a pcap file to read from.  Otherwise `pcapSource` is treated
  as a stream providing pcap data.
* `address` {String} An IPv4 address used in the pcap file.  The dgram socket
  will act as that IP address.  Packets sent to this address will be emitted
  via the `'message'` event.
* `opts` {Object | null} Optional parameters
  * `port` {Number | null} The UDP port associated with the `address`
    passed as the second argument.  Packets sent to this port at the given
    address wil be emitted via the `'message'` event. If not provided then
    the port will be automatically set to the port used on the first UDP
    packet sent to the address.
  * `netmask` {String} An IPv4 netmask to use when pretending to be the
    configured `address`.  This mainly determines if packets sent to subnet
    specific broadcast addresses.  For example, setting a netmask of
    `'255.255.255.0'` will cause the socket to deliver packets addressed
    like this `'192.168.1.255'`.  Defaults to `'255.255.255.255'` meaning
    only unicast and full broadcast will packets will be delivered.

### pdgram.start()

Start the flow of packets.  The `'listening'` event will be emitted at this
point.  If this is not called, then data will back up and eventually be
dropped depending on how many packets are in the pcap file.

### Event 'output'

The `'output'` event will fire whenever the `send()` fuction is called.
Instead of writing the data out to the specified remote host, the data is
provided to this event instead.  This allows test code to validate that
the correct output is being produced by the code under test.

* `msg` {Buffer} The UDP payload to send to the remote host
* `port` {Number} The UDP port of the remote host
* `address` {Address} The IPv4 address of the remote host

[dgram.Socket]: http://nodejs.org/api/dgram.html#dgram_class_socket
