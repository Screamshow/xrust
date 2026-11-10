# Chrome 155 capture

The binary fixture is the initial TLS record from Xray-core 26.11.9 (676eaf6,
Linux x86-64, uTLS a13c59ffe98b). A loopback VLESS outbound used TLS with
fingerprint chrome, SNI www.gstatic.com and ALPN h2 followed by http/1.1.
The socket closed after the ClientHello.
