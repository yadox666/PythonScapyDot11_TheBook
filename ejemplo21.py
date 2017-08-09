Ejemplo en consola:

>>> captura=rdpcap('proberequest.cap')
>>> captura.summary()
>>> wireshark(captura)
>>> captura=rdpcap('/tmp/proberequest.cap').filter(lambda p:(Dot11ProbeResp in p))
>>> len(cap)

