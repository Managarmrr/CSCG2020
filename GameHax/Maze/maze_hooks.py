import logging
import struct
from typing import Union

from ctfutils.proxy.hook import UDPProxyHook, PresetFilters

logger = logging.getLogger('ProxyHooks')


class EncryptionHook(UDPProxyHook):
    PRIO = 1

    USE_NULL_KEY = True
    message_key = b'\0\0'

    @staticmethod
    def expand_key(key):
        if len(key) < 2:
            raise ValueError('The key seed needs to be at least 2 bytes')

        key_byte = key[0]
        while True:
            yield key_byte
            tmp = key_byte + key[1]
            key_byte = (tmp + ((tmp * 0x80808081) >> 39)) & 0xff

    @staticmethod
    def encrypt(message: Union[bytes, bytearray]) -> bytes:
        key = b'\0\0'
        encrypted = key + bytearray(([x ^ y for x, y in
                                      zip(message, EncryptionHook.expand_key(key))]))

        return encrypted

    def pre_filter(self) -> None:
        """Decrypt"""
        if len(self.message) < 2:
            return

        self.message_key = self.message[0:2]
        self.message = bytearray(([x ^ y for x, y in
                                   zip(self.message[2:], self.expand_key(self.message_key))]))

    def post_filter(self) -> None:
        """Encrypt"""
        key = b'\0\0' if self.USE_NULL_KEY else self.message_key
        self.message = key + bytearray(([x ^ y for x, y in
                                         zip(self.message, self.expand_key(key))]))


class LoginHook(UDPProxyHook):
    PRIO = 1

    def filter_(self) -> None:
        # Set the other ends client upstream address to our client
        # In short: switch client as soon as a new one logs in
        self.global_data['secret'] = self.message[1:9]
        print(f'Switching to new downstream client: {self.client_address}')
        self.this_server.upstream_address = self.client_address


class ClientPositionHook(UDPProxyHook):
    def filter_(self) -> None:
        block = self.global_data.get('block_client_posupdate', False)

        if block:
            self.message = bytearray(0)
            return

        x, y, z = [x / 10000 for x in struct.unpack('<III', self.message[17:29])]
        time = struct.unpack('<Q', self.message[9:17])[0] / 10000
        self.global_data['position_time'] = time
        self.global_data['player_position'] = (x, y, z)

        y_adjust = self.global_data.get('vhover_height', 0)
        if y_adjust != 0:
            self.message = (self.message[0:21] +
                            struct.pack('<I', int(10000 * (y + y_adjust))) +
                            self.message[25:])


class NPCPositionHook(UDPProxyHook):
    def filter_(self) -> None:
        offset = 1
        while offset < len(self.message):
            uid = struct.unpack('<I', self.message[offset:offset + 4])[0]
            x, y, z = [x / 10000.0 for x in
                       struct.unpack('<III', self.message[offset + 12:offset + 24])]

            if 'tracking_data' not in self.global_data:
                self.global_data['tracking_data'] = {}

            if uid == self.global_data.get('tracked_player', 0):
                pos = (x, z)
                if uid not in self.global_data['tracking_data']:
                    self.global_data['tracking_data'][uid] = [pos]
                else:
                    if pos not in self.global_data['tracking_data'][uid]:
                        self.global_data['tracking_data'][uid].append(pos)

            offset += 42


class NPCInformationHook(UDPProxyHook):
    def filter_(self) -> None:
        uid = struct.unpack('<I', self.message[1:5])[0]
        name = self.message[8:].decode()

        if 'npcs' in self.global_data:
            self.global_data['npcs'][uid] = name
        else:
            self.global_data['npcs'] = {uid: name}


class LoggingHook(UDPProxyHook):
    def filter_(self) -> None:
        logger.info(f'From upstream: {self.from_upstream}\n\tMessage: {self.message} ({len(self.message)})')


MAZE_HOOKS = {
    EncryptionHook: PresetFilters.match_never,
    LoggingHook: PresetFilters.not_starts_with(
        [b'<', b'E', b'I', b'L', b'P', b'Y', b'R', b'T']),
    LoginHook: PresetFilters.starts_with(b'L', match_downstream=False),
    ClientPositionHook: PresetFilters.starts_with(b'P', match_downstream=False),
    NPCInformationHook: PresetFilters.starts_with(b'I', match_upstream=False),
    NPCPositionHook: PresetFilters.starts_with(b'P', match_upstream=False),
}
