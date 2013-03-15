# pcap-dgram

Mock UDP socket based on pcap file data.

[![Build Status](https://travis-ci.org/wanderview/node-pcap-dgram.png)](https://travis-ci.org/wanderview/node-pcap-dgram)

## Example

```javascript
'use strict';

var PcapDgram = require('pcap-dgram');
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
  pdgram.output.on('readable', function() {
    var msg = pdgram.output.read();
    test.equal(hello.toString(), msg.data.toString());
    test.equal(remotePort, msg.udp.dstPort);
    test.equal(remoteAddr, msg.ip.dst);
  });

  pdgram.on('close', function() {
    test.done();
  });

  // because we constructor pdgram with {paused:true} we must explicitly start
  pdgram.resume();
};
```

## Limitations / TODO

* Currently only supports IPv4.

## Class PcapDgram

The PcapDgram class implements the same API as the [dgram.Socket][] class.
Data is delivered to the `'message'` event by reading data from a pcap
file.  Outgoing data is redirected to the `output` stream so that it
can be validated for correctness.

### var pdgram = new PcapDgram(pcapSource, address, opts)

* `pcapSource` {String | Stream} If a String, pcapSource is interpreted as
  the name of a pcap file to read from.  Otherwise `pcapSource` is treated
  as a stream providing pcap data.
* `address` {String} An IPv4 address used in the pcap file.  The dgram socket
  will act as that IP address.  Packets sent to this address will be emitted
  via the `'message'` event.
* `opts` {Object | null} Optional parameters
  * `port` {Number} The UDP port associated with the `address`
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
  * `paused` {Boolean} If true, the PcapDgram will start in the paused state
    and will not emit any `'message'` events until `resume()` is called.

### pdgram.pause()

Stop the flow of packets.  Note, if the stream is paused for too long, the
underlying buffer may not be able support the number of pcap packets and
begin dropping data.

### pdgram.resume()

Start the flow of packets after `pause()` has been called or the if PcapDgram
was created with the `{paused: true}` option.  Note, if `{paused: true}` was
used during construction, then the `'listening'` event will not be emiited
until the first time `resume()` is called.

### pdgram.output

All messages passed to the `send()` function will be available to be read
from the `pdgram.output` passthrough stream.  This allows test code to validate
that the correct output is being produced by the code under test.

The messages available on the `output` stream look like this:

* `msg` {Object} The object representing the sent message.
  * `data` {Buffer} The UDP payload to send to the remote host
  * `ip` {Object} Object providing IP related information for the message
    * `dst` {String} The IPv4 address of the remote host
    * `src` {String} The IPv4 address configured on the mock dgram
    * `protocol` {String} Always contains the value `'udp'`
  * `udp` {Object} Object providing UDP related information for the message
    * `dstPort` {Number} The UDP port of the remote host
    * `srcPort` {Number} The UDP port configured on the mock dgram
    * `dataLength` {Number} The number of bytes in the `data` buffer

[dgram.Socket]: http://nodejs.org/api/dgram.html#dgram_class_socket
