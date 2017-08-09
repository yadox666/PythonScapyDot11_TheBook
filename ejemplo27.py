#!/usr/bin/python
# -*- coding: utf-8 -*-​
import serial, time
from pynmea import nmea

sport='/dev/ttyUSB0'
sbaud=4800
stimeout = 1 # timeout (in seconds) so that the port doesn't hang
ser=0
verbose=1

def init_serial():
    global ser
    ser = serial.Serial()
    ser.baudrate = sbaud
    ser.port = sport
    ser.timeout = stimeout
    ser.open()
    print 'Serial port: ' + ser.portstr


#### Main Thread
init_serial()

while 1:
    try:
        data = ser.readline()   ## reads in bytes followed by a newline
	print 'NMEA Phrase: ' + data
	if data[0:6] == '$GPGGA':
            gpgga = nmea.GPGGA()
            gpgga.parse(data)
            if verbose: print 'GPS NMEA: ' + data   ## print to the console
            print 'GPS timestamp: ' + gpgga.timestamp
            print 'GPS sats,qual: ' + gpgga.num_sats + ',' + gpgga.gps_qual
            print 'GPS lon,lat: ' + gpgga.longitude + ',' + gpgga.latitude
	if data[0:6] == '$GPRMC':
	    gprmc = nmea.GPRMC()
	    gprmc.parse(data)
            print 'GPS timestamp: ' + gprmc.timestamp

    except serial.SerialException as e:  ## There is no new data from serial port
        pass
    except TypeError as e:  ## Disconnect of USB->UART occured
        ser.port.close()
        break
    except KeyboardInterrupt as e:  ## Disconnect of USB->UART occured
        ser.port.close()
	break
    else:    ## Some data was received
        pass

