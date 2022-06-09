import serial
import asyncio
import websockets
from pyencoder import encode_message

class AISerial:
    """
    Class for handling serial com for input, and SDR output
    The don't listen argument is to prevent the creation of multiple serial port
    """
    def __init__(self, dont_listen=False, retransmit=False):
        if not dont_listen:
            self.serial_port = serial.Serial(
                    port="/dev/ttyUSB0", baudrate=38400, bytesize=8, timeout=2, stopbits=serial.STOPBITS_ONE
                )
        if retransmit:
            self.serial_retransmit = serial.Serial(
                port="/dev/ttyUSB1", baudrate=38400, bytesize=8, stopbits=serial.STOPBITS_ONE
            )

    def receive_phrase(self):
        """
        Blocking function which reads com port until "\\r\\n"
        """
        phrase = b""
        while not phrase:
            phrase = self.serial_port.read_until(b"\r\n")

        return phrase

    async def _send_async(self, msg):
        """
        Private function to send a message to websocket of ais simulator
        """
        async with websockets.connect("ws://localhost:52002") as ws:
            await ws.send(msg)

    def send_phrase(self, d):
        """
        Accept a dict with keys msg_type or type, and specific info for each type
        """
        string = encode_message(d)
        asyncio.run(self._send_async(string))

    def retransmit(self, msg):
        self.serial_retransmit.write(msg)