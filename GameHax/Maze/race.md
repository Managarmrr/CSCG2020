# Maze - Maze Runner // Maze - M4z3 Runn3r

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
**Difficulty**: `Medium` // `Hard`  
**Author**: `LiveOverflow`  
**Attachments**: [Maze_v2_windows.zip](https://static.allesctf.net/challenges/95a402a5b93a4424bcba9a46a0c9ef153025da6fe4aa57c6d35769d0c2a70878/Maze_vS2_windows.zip)
[Maze_v2_linux.zip](https://static.allesctf.net/challenges/a55b8a3e191c55ebea44fb126bee8b66cac3ac8d2229a725c8544787fad79e0c/Maze_v2_linux.zip)
[Maze_v2_mac.zip](https://static.allesctf.net/challenges/e3f1390bc36214cc769ce77dbbe2d78db4775eb6ddb6a821718c91d00be480a9/Maze_v2_mac.zip)  
**Description**:

Can you complete the scorch trials? //
Complete the scorch trials in under 5 seconds!

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

This challenge is a bit different from the other `Maze` challenges as this one
is about a race minigame. We just need to complete the race in under 5 seconds.
Upon attempting a legit run we quickly discover, that completing the race - let
alone in under 5 seconds - is impossible without cheating. Playing around with
the network traffic we learn that we are able to teleport ourselves and have
the client send a new position - or even report a different position ourselves.

Unfortunately the delta of the old and position may not exceed a length of 10
(excluding evelation (`y`)). Meaning we have to teleport short distances in
quick succession - unfortunately the server does not like this either. But upon
closer inspection of the position update packages we can see that a time is
transmitted as well - manipulating it allows us to teleport in quick succession.

This means that the server has an absolute check of 10 the delta may not exceed,
with an additional check which verifies that the client does not move too fast -
fortunately for us the server just trusts our time.

The first step to solving this challenge would be to farm all checkpoint
coordinates. In order to do this we just need to implement two commands and a
hook:

```python
def get_position(global_data, **kwargs):
    print(global_data['player_position'])

def show_checkpoint(command, downstream, **kwargs):
    if len(command) < 2:
        print(f'USAGE: {command[0]} [id]')
        return

    for i in range(int(command[1])):
        packet = b'\0\0R' + bytes([i])
        downstream.send(packet)
        time.sleep(0.1)

COMMANDS = {
    'getpos': get_position,
    'sc': show_checkpoint
}
```

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

After which we will be able to farm the coordinates:

```python
RACE_COORDS = [
    (203.5232, 0.0, 193.97),    # Checkpoint 0
    (180.7177, 0.0, 179.1121),  # Checkpoint 1
    (172.5663, 0.0, 207.8936),  # Checkpoint 2
    (187.6264, 0.0, 232.8247),  # Checkpoint 3
    (165.4655, 0.0, 232.3275),  # Checkpoint 4
    (150.6674, 0.0, 186.3977),  # Checkpoint 5
    (180.0567, 0.0, 162.1102),  # Checkpoint 6
    (165.3552, 0.0, 118.4615),  # Checkpoint 7
    (121.4415, 0.0, 96.3562),   # Checkpoint 8
    (119.7501, 0.0, 126.09),    # Checkpoint 9
    (112.2867, 0.0, 194.0876),  # Checkpoint 10
    (75.7412, 0.0, 208.8779),   # Checkpoint 11
    (60.3128, 0.0, 208.8806)    # Checkpoint 12
]
```

Now all that's left is implementing the race command and adjusting our hook:

```python
def race(global_data, upstream, **kwargs):
    global_data['block_client_posupdate'] = True

    race_coords = RACE_COORDS
    pos = global_data['player_position']
    pos = (pos[0], 0, pos[2])

    prefix = b'\0\0P' + global_data['secret']

    # noinspection PyShadowingNames
    def update_pos(delta_, pos, time_):
        pos = [x + y for x, y in zip(pos, delta_)]
        time_ += 2
        upstream.send(prefix +
                      struct.pack('<QIII', int(time_ * 10000),
                                  *[int(x * 10000) for x in pos]) +
                      bytearray(17))

        return pos, time_

    time_ = global_data['position_time']
    for target in race_coords:
        delta = [y - x for x, y in zip(pos, target)]
        magnitude = math.sqrt(sum([x ** 2 for x in delta]))

        if magnitude > 10:
            scaling = round(9 / magnitude, 4)
            scaled = [x * scaling for x in delta]
            while magnitude > 10:
                pos, time_ = update_pos(scaled, pos, time_)
                magnitude -= 9

            delta = [y - x for x, y in zip(pos, target)]

        pos, time_ = update_pos(delta, pos, time_)

    global_data['block_client_posupdate'] = False

COMMANDS = {
    'getpos': get_position,
    'sc': show_checkpoint,
    'race': race
}
```

```python
class ClientPositionHook(UDPProxyHook):
    def filter_(self) -> None:
        block = self.global_data.get('block_client_posupdate', False)

        if block:
            self.message = bytearray(0) # Discard
            return

        x, y, z = [x / 10000 for x in struct.unpack('<III', self.message[17:29])]
        time = struct.unpack('<Q', self.message[9:17])[0] / 10000
        self.global_data['position_time'] = time
        self.global_data['player_position'] = (x, y, z)

MAZE_HOOKS = {
    EncryptionHook: PresetFilters.match_never,
    LoggingHook: PresetFilters.match_always,
    LoginHook: PresetFilters.starts_with(b'L', match_downstream=False),
    ClientPositionHook: PresetFilters.starts_with(b'P', match_downstream=False)
}
```

Running the `race` command we can observe the server teleporting us back because
we end up in no-tp-zones (walls). In order to fix this we just need to partially
run the mace command by adjusting the slice of `RACE_COORDS` and insert
alignment vectors. This won't result in the ideal route, but who cares really.

```python
RACE_COORDS = [
    (203.5232, 0.0, 193.97),    # Checkpoint 0
    (180.7177, 0.0, 179.1121),  # Checkpoint 1
    (167.5089, 0.0, 186.2246),  # Alignment vector
    (176.9194, 0.0, 217.278),   # Alignment vector
    (186.169, 0.0, 225.2751),   # Alignment vector
    (172.5663, 0.0, 207.8936),  # Checkpoint 2
    (187.6264, 0.0, 232.8247),  # Checkpoint 3
    (183.6915, 0.0, 237.3451),  # Alignment vector
    (176.3615, 0.0, 238.329),   # Alignment vector
    (165.4655, 0.0, 232.3275),  # Checkpoint 4
    (150.4808, 0.0, 212.0976),  # Alignment vector
    (150.6674, 0.0, 186.3977),  # Checkpoint 5
    (155.035, 0.0, 165.0394),   # Alignment vector
    (180.0567, 0.0, 162.1102),  # Checkpoint 6
    (177.4812, 0.0, 134.8266),  # Alignment vector
    (165.3552, 0.0, 118.4615),  # Checkpoint 7
    (147.7148, 0.0, 100.3988),  # Alignment vector
    (121.4415, 0.0, 96.3562),   # Checkpoint 8
    (113.6536, 0.0, 113.976),   # Alignment vector
    (119.7501, 0.0, 126.09),    # Checkpoint 9
    (127.0356, 0.0, 129.3163),  # Alignment vector
    (124.6458, 0.0, 137.3901),  # Alignment vector
    (124.3621, 0.0, 144.1631),  # Alignment vector
    (112.2867, 0.0, 194.0876),  # Checkpoint 10
    (94.5945, 0.0, 195.8559),   # Alignment vector
    (86.3372, 0.0, 195.8754),   # Alignment vector
    (75.7412, 0.0, 208.8779),   # Checkpoint 11
    (60.3128, 0.0, 208.8806)    # Checkpoint 12
]
```

Running the `race` once more we are rewarded with to flags:
`CSCG{N3VER_TRUST_T1111ME}` (`M4z3 Runn3r`) and
`CSCG{SPEEDH4X_MAZE_RUNNER_BUNNYYYY}` (`Maze Runner`)

## 8. Mitigations

In order to mitigate this exploit, the server should not trust client-side data
and enforce speed limits with tick times more strictly. Also the race should
follow tick time, not real time - two measures of time is a recipe for disasters
anyway.
