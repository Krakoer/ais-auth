#!/usr/bin/env python
#
# Copyright 2013-2014 -- Embyte & Pastus
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
from Crypto.Util.number import long_to_bytes, bytes_to_long
import math
from bitstring import Bits

# Adapted from gpsd-3.9's driver_ais.c
def encode_string(string):
	vocabolary = "@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^- !\"#$%&'()*+,-./0123456789:;<=>?"
	encoded_string = ""
	for c in string.upper():
		index = vocabolary.find(c)
		encoded_string += '{0:b}'.format(index).rjust(6,'0')
	return encoded_string

# NB. We add a mask to tell python how long is our rapresentation (overwise on negative integers, it cannot do the complement 2).
def compute_long_lat (__long, __lat):
	_long = '{0:b}'.format(int(round(__long*600000)) & 0b1111111111111111111111111111).rjust(28,'0')
	_lat =  '{0:b}'.format(int(round(__lat*600000))  & 0b111111111111111111111111111).rjust(27,'0')
	return (_long, _lat)

def compute_long_lat22 (__long, __lat):
	_long = '{0:b}'.format(int(round(__long*600)) & 0b111111111111111111).rjust(18,'0')
	_lat =  '{0:b}'.format(int(round(__lat*600))  & 0b11111111111111111).rjust(17,'0')
	return (_long, _lat)

def encode_1(mmsi, status=15, speed=0, lon=0, lat=0, course=0, second=0, repeat=0, turn=128, accuracy=0, heading=0, maneuver=0, spare_1=b'\x00', raim=0, radio=0):
	_type = '{0:b}'.format(1).rjust(6,'0')				# 18
	_repeat = '{0:b}'.format(repeat).rjust(2,'0')		# repeat (directive to an AIS transceiver that this message should be rebroadcast.)
	_mmsi = '{0:b}'.format(mmsi).rjust(30,'0')		# 30 bits (247320162)
	_status = '{0:b}'.format(status).rjust(4,'0')			#  navigation status e.g. 0=Under way using engine, 1-At anchor, 5=Moored, 8=Sailing,15=undefined

	_rot = Bits(int=int(turn), length=8).bin				# rate of turn 

	_speed = '{0:b}'.format(int(round(speed*10))).rjust(10,'0')	# Speed over ground is in 0.1-knot resolution from 0 to 102 knots. value 1023 indicates speed is not available, value 1022 indicates 102.2 knots or higher.
	_accuracy = '{0:b}'.format(accuracy)[0]									# > 10m

	(_long, _lat) = compute_long_lat(lon, lat)

	_course = '{0:b}'.format(int(round(course*10))).rjust(12,'0')	# 0.1 resolution. Course over ground will be 3600 (0xE10) if that data is not available.
	_true_heading = '{0:b}'.format(int(heading)).rjust(9,'0')	# 511 (N/A)
	_ts = '{0:b}'.format(second).rjust(6,'0') # Second of UTC timestamp.

	_flags = ""
	_flags += '{0:b}'.format(maneuver).rjust(2,'0')
	_flags += "000" # Spare
	_flags += '{0:b}'.format(raim)[0]

	_rstatus = '{0:b}'.format(radio).rjust(19,'0') # ??

	msg = _type+_repeat+_mmsi+_status+_rot+_speed+_accuracy+_long+_lat+_course+_true_heading+_ts+_flags+_rstatus
	assert len(msg) == 168
	return msg


def encode_6(mmsi, msg, fid, dac, dest_mmsi):
	_type= "{0:b}".format(6).rjust(6, '0')				# 6
	_repeat = "00"										# repeat (directive to an AIS transceiver that this message should be rebroadcast.)
	_mmsi = '{0:b}'.format(mmsi).rjust(30,'0')		# 30 bits (247320162)
	_seqno = "00"										# spare bit
	_dest_mmsi = '{0:b}'.format(dest_mmsi).rjust(30,'0')
	_retransmit = "0"
	_spare = "0"
	_dac = '{0:b}'.format(dac).rjust(10,'0')			# Designated Area Code (10 bits)
	_fid = '{0:b}'.format(fid).rjust(6,'0')           # FID 6 bits
	_msg = bin(bytes_to_long(msg))[2:]
	return _type+_repeat+_mmsi+_seqno+_dest_mmsi+_retransmit+_spare+_dac+_fid+_msg

def encode_8(mmsi, data, fid=0, dac=0):
	_type= "{0:b}".format(8).rjust(6, '0')				# 8
	_repeat = "00"										# repeat (directive to an AIS transceiver that this message should be rebroadcast.)
	_mmsi = '{0:b}'.format(mmsi).rjust(30,'0')		# 30 bits (247320162)
	_spare = "00"										# spare bit
	_dac = '{0:b}'.format(dac).rjust(10,'0')			# Designated Area Code (10 bits)
	_fid = '{0:b}'.format(fid).rjust(6,'0')           # FID 6 bits
	_data = bin(bytes_to_long(data))[2:]
	_data = _data.rjust((len(_data)+7)&(-8), "0")		# Round to next byte
	return _type+_repeat+_mmsi+_spare+_dac+_fid+_data


def encode_message(d:dict):
	"""
	Accepts a dict and returns binary string ready to be sent to sockets
	"""
	msg_type = d.pop("msg_type")
	if msg_type == 1:
		return encode_1(**d)
	elif msg_type == 8:
		return encode_8(**d)
	elif msg_type == 6:
		return encode_6(**d)
	else:
		raise NotImplementedError(f"Message type {msg_type} not yet supported")