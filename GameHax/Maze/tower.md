# Maze - Tower

**Author**: `Managarmr`

## Table of Contents

1. [Challenge](#1-challenge)
2. [Having a look](#2-having-a-look)
3. [Checking out the network traffic](#3-checking-out-the-network-traffic)
4. [Checking out the GameAssembly](#4-checking-out-the-gameassembly)
5. [Decrypting the network traffic](#5-decrypting-the-network-traffic)
6. [Hijacking the session](#6-hijacking-the-session)
7. [Solving the challenge](#7-solving-the-challenge)
8. [Mitigations](#8-mitigations)

## 1. Challenge

**Category**: `Gamehax`  
**Difficulty**: `Easy`  
**Author**: `LiveOverflow`  
**Attachments**: [Maze_v2_windows.zip](https://static.allesctf.net/challenges/95a402a5b93a4424bcba9a46a0c9ef153025da6fe4aa57c6d35769d0c2a70878/Maze_v2_windows.zip)
[Maze_v2_linux.zip](https://static.allesctf.net/challenges/a55b8a3e191c55ebea44fb126bee8b66cac3ac8d2229a725c8544787fad79e0c/Maze_v2_linux.zip)
[Maze_v2_mac.zip](https://static.allesctf.net/challenges/e3f1390bc36214cc769ce77dbbe2d78db4775eb6ddb6a821718c91d00be480a9/Maze_v2_mac.zip)  
**Description**:

Find a path to reach the tower and climb to the top.

See also: `maze.liveoverflow.com`

## 2. Having a look

This challenge is a game challenge and the provided files are clients for a
multiplayer game. This really is a nice touch for a CTF.

## 3. Checking out the network traffic

As this is a multiplayer game it only makes sense to check out the network
traffic. There are multiple valid ways how someone could approach this kind of
challenges in this writeup we will only be focusing on the network side of
things. (This is because I'm very lazy to be honest and I didn't feel like
hooking)

Upon inspecting the network traffic after attaching an `UDP` proxy we can not
see very much.

Our proxy configuration looks as follows: (I am using a custom framework which
I will not include here, but all names should be self-explanatory)

```python
#!/usr/bin/env python3
import logging
import random
import threading
from importlib import reload

import maze_commands
import maze_hooks
from ctfutils.proxy.mitm import UDPMitmProxy

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

global_data = {}

upstream = UDPMitmProxy(
    bind_address=('0.0.0.0', random.randrange(20000, 2 ** 16)),
    upstream_address=('maze.liveoverflow.com', 1338), is_upstream=True,
    global_data=global_data)

downstream = UDPMitmProxy(
    bind_address=('localhost', 13337), other_end=upstream,
    global_data=global_data)
upstream.other_end = downstream

upstream.register_volatile_hooks(maze_hooks, 'MAZE_HOOKS')
downstream.register_volatile_hooks(maze_hooks, 'MAZE_HOOKS')

upstream_thread = threading.Thread(target=upstream.serve_forever)
downstream_thread = threading.Thread(target=downstream.serve_forever)

if __name__ == '__main__':
    print('Starting UDP proxy')
    upstream_thread.start()
    downstream_thread.start()

    while True:
        try:
            cmd = input('> ').split(' ')
            if len(cmd) == 0:
                continue

            if cmd[0].lower() in ('q', 'quit', 'exit'):
                raise KeyboardInterrupt()

            try:
                reload(maze_commands)
                if cmd[0].lower() in maze_commands.COMMANDS:
                    func = maze_commands.COMMANDS[cmd[0].lower()]
                    func(command=cmd, global_data=global_data,
                         upstream=upstream, downstream=downstream)
                    continue
            except Exception as e:
                print(f'Error evaluating command {cmd}:', e)
                continue

            print(f'Unknown command: {cmd}')
        except (EOFError, KeyboardInterrupt):
            print('Stopping UDP proxy')
            upstream.shutdown()
            downstream.shutdown()
            upstream_thread.join()
            downstream_thread.join()
            break
```

The hooks looking like this:

```python
import logging

from ctfutils.proxy.hook import UDPProxyHook, PresetFilters

logger = logging.getLogger('ProxyHooks')

class LoggingHook(UDPProxyHook):
    def filter_(self) -> None:
        logger.info(f'From upstream: {self.from_upstream}\n\tMessage: {self.message} ({len(self.message)})')

MAZE_HOOKS = {
    LoggingHook: PresetFilters.match_always
}
```

The data seems random, which could indicate encryption. So we really do have
to have a look at the `GameAssembly.so` and find out how to interpret the
network data.

## 4. Checking out the GameAssembly

The game appears to be built with the help of `il2cpp` according to the strings
within the `GameAssembly.so`. Luckily for us there are tools available that
help recover function names and structures. We are using
[il2cppdumper](https://github.com/Perfare/Il2CppDumper).

Having a look at the processed `GameAssembly.so` in `IDA` we can see some
interesting functions, one of them being `ServerManager$$sendData`:

```c
  if ( (int)pkt_->max_length > 0 )
  {
    LODWORD(v21) = pkt_->max_length;
    v25 = 0x200000000LL;
    v27 = 0LL;
    v23 = 2155905153LL;
    v24 = 0x100000000LL;
    do
    {
      if ( v27 >= (unsigned int)v21 )
      {
        v38 = 0LL;
        v33 = sub_2BC6E0(*(_QWORD *)&qword_113C4B0, "System", "IndexOutOfRangeException", &v38);
        sub_322D10(v33, 0LL);
      }
      v28 = v27 + 2;
      if ( v27 + 2 >= (unsigned int)v26 )
      {
        v38 = 0LL;
        v34 = sub_2BC6E0(*(_QWORD *)&qword_113C4B0, "System", "IndexOutOfRangeException", &v38);
        sub_322D10(v34, 0LL);
      }
      final_packet->m_Items[v25 >> 32] = v17 ^ pkt_->m_Items[v27];
      v29 = final_packet->max_length;
      if ( (unsigned int)v29 <= 1 )
      {
        v38 = 0LL;
        v35 = sub_2BC6E0(*(_QWORD *)&qword_113C4B0, "System", "IndexOutOfRangeException", &v38);
        sub_322D10(v35, 0LL);
      }
      v26 = (unsigned int)v29;
      v30 = (unsigned __int8)v17 + (unsigned int)final_packet->m_Items[1];
      v17 = v30 + ((unsigned __int64)(2155905153LL * v30) >> 39);
      v21 = LODWORD(pkt_->max_length);
      v25 += 0x100000000LL;
      v27 = v28 - 1;
    }
    while ( v28 - 1 < (int)v21 );
  }
```

## 5. Decrypting the network traffic

So now that we know how the network traffic is encrypted we just have to add a
new hook and it will take care of it transparently.

```python
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

MAZE_HOOKS = {
    EncryptionHook: PresetFilters.match_never,
    LoggingHook: PresetFilters.match_always
}
```

## 6. Hijacking the session

In order to effectively take over the session we need to keep track of our
client secret and some other metadata. For exactly this use case the framework
includes the concept of global and proxy shared data. We will only use global
shared data in this case, but we still need to collect some information.

In order to grab all the required data we will need to implement a `LoginHook`:

```python
class LoginHook(UDPProxyHook):
    PRIO = 2

    def filter_(self) -> None:
        # Set the other ends client upstream address to our client
        # In short: switch client as soon as a new one logs in
        self.global_data['secret'] = self.message[1:9]
        print(f'Switching to new downstream client: {self.client_address}')
        self.this_server.upstream_address = self.client_addres

MAZE_HOOKS = {
    EncryptionHook: PresetFilters.match_never,
    LoggingHook: PresetFilters.match_always,
    LoginHook: PresetFilters.starts_with(b'L', match_downstream=False)
}
```

## 7. Solving the challenge

In order to solve the challenge the description implies we only need to reach
the top of a distant tower. We can implement a command to teleport us into the
air client-side, allowing us to look around without even modifying the client:

```python
def teleport_up(command, global_data, downstream, **kwargs):
    if len(command) < 2:
        height = 100
    else:
        height = int(command[1])

    new_pos = global_data['player_position']
    new_pos = (new_pos[0], new_pos[1] + height, new_pos[2])
    packet = b'T\x01' + struct.pack('<III', *[int(x * 10000) for x in new_pos])
    downstream.send(packet)

COMMANDS = {
    'up': teleport_up
}
```

This command utilises a server-sent teleport packet (used for teleportes).

After locating the tower it is just a question of reaching it - which is trivial
when using the up command and two additional command in order to teleport
through walls (the server only allow for a delta vector of length 10 or less,
disregarding changes in `y`):

```python
def get_position(global_data, **kwargs):
    print(global_data['player_position'])

def teleport_relative(command, global_data, **kwargs):
    x, y, z = global_data['player_position']

    target_x = float(command[1]) if len(command) > 1 else x
    target_y = float(command[2]) if len(command) > 2 else y
    target_z = float(command[3]) if len(command) > 3 else z

    new_pos = (target_x, target_y, target_z)
    packet = b'T\x01' + struct.pack('<III', *[int(x * 10000) for x in new_pos])
    downstream.send(packet)

COMMANDS = {
    'up': teleport_up,
    'getpos': get_position,
    'rtp': teleport_relative
}
```

In order for the location tracking to work we have to add a new hook:

```python
class ClientPositionHook(UDPProxyHook):
    def filter_(self) -> None:
        x, y, z = [x / 10000 for x in struct.unpack('<III', self.message[17:29])]
        self.global_data['player_position'] = (x, y, z)

MAZE_HOOKS = {
    EncryptionHook: PresetFilters.match_never,
    LoggingHook: PresetFilters.match_always,
    LoginHook: PresetFilters.starts_with(b'L', match_downstream=False),
    ClientPositionHook: PresetFilters.starts_with(b'P', match_downstream=False)
}
```

Eventually reaching the top of the tower results in us obtaining the flag
`CSCG{SOLVED_THE_MAZE...LONG_WAY_BACK!}`.

## 8. Mitigations

In order to mitigate this exploit, the server should strictly enforce how high
a player can be at any moment and the walls (no-tp-zones) should be at least 10
thick.
