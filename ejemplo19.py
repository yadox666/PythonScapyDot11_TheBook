# Ejemplo en consola:

# >>> captura=sniff(iface='mon0',count=3, lfilter=lambda pkt:(Dot11ProbeReq in pkt))
# >>> captura.summary()
# >>> wrpcap('./proberequest.cap',captura)
# >>> quit()
# tcpdump -r proberequest.cap 

print "Lea el fichero ejemplo19.py para ver su contenido"

