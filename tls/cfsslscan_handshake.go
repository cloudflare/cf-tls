package tls

import "errors"

// SayHello constructs a simple Client Hello to a server, parses its serverHelloMsg response
// and returns the negotiated ciphersuite ID
func (c *Conn) SayHello() (cipherID, version uint16, err error) {
	hello := &clientHelloMsg{
		vers:                c.config.maxVersion(),
		compressionMethods:  []uint8{compressionNone},
		random:              make([]byte, 32),
		ocspStapling:        true,
		serverName:          c.config.ServerName,
		supportedCurves:     c.config.curvePreferences(),
		supportedPoints:     []uint8{pointFormatUncompressed},
		nextProtoNeg:        len(c.config.NextProtos) > 0,
		secureRenegotiation: true,
		cipherSuites:        c.config.cipherSuites(),
		signatureAndHashes:  allSignatureAndHashAlgorithms,
	}
	serverHello, err := c.sayHello(hello)
	if err != nil {
		return
	}
	cipherID, version = serverHello.cipherSuite, serverHello.vers
	return

}

// sayHello is the backend to SayHello that returns a full serverHelloMsg for processing.
func (c *Conn) sayHello(hello *clientHelloMsg) (serverHello *serverHelloMsg, err error) {
	c.writeRecord(recordTypeHandshake, hello.marshal())
	msg, err := c.readHandshake()
	if err != nil {
		return
	}
	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return nil, errors.New("invalid ServerHello")
	}
	return
}
