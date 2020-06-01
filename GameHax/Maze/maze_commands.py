import math
import struct
import time

import matplotlib.pyplot as plt


def send_emote(command, global_data, upstream, **kwargs):
    if len(command) < 2:
        print(f'USAGE: {command[0]} [id] (hex)')
        return

    packet = b'\0\0E' + global_data['secret'] + bytearray.fromhex(command[1])
    upstream.send(packet)


def get_position(global_data, **kwargs):
    print(global_data['player_position'])


def teleport_up(command, global_data, downstream, **kwargs):
    if len(command) < 2:
        height = 100
    else:
        height = int(command[1])

    new_pos = global_data['player_position']
    new_pos = (new_pos[0], new_pos[1] + height, new_pos[2])
    packet = b'\0\0T\x01' + struct.pack('<III', *[int(x * 10000) for x in new_pos])
    downstream.send(packet)


def virtual_hover(command, global_data, **kwargs):
    if len(command) < 2:
        height = 0
    else:
        height = float(command[1])

    global_data['vhover_height'] = height
    print(f'Virtual hover height set to {height}')


def show_checkpoint(command, downstream, **kwargs):
    if len(command) < 2:
        print(f'USAGE: {command[0]} [id]')
        return

    for i in range(int(command[1])):
        packet = b'\0\0R' + bytes([i])
        downstream.send(packet)
        time.sleep(0.1)


RACE_COORDS = [
    (203.5232, 0.0, 193.97),  # Checkpoint 0
    (180.7177, 0.0, 179.1121),  # Checkpoint 1
    (167.5089, 0.0, 186.2246),  # Alignment vector
    (176.9194, 0.0, 217.278),  # Alignment vector
    (186.169, 0.0, 225.2751),  # Alignment vector
    (172.5663, 0.0, 207.8936),  # Checkpoint 2
    (187.6264, 0.0, 232.8247),  # Checkpoint 3
    (183.6915, 0.0, 237.3451),  # Alignment vector
    (176.3615, 0.0, 238.329),  # Alignment vector
    (165.4655, 0.0, 232.3275),  # Checkpoint 4
    (150.4808, 0.0, 212.0976),  # Alignment vector
    (150.6674, 0.0, 186.3977),  # Checkpoint 5
    (155.035, 0.0, 165.0394),  # Alignment vector
    (180.0567, 0.0, 162.1102),  # Checkpoint 6
    (177.4812, 0.0, 134.8266),  # Alignment vector
    (165.3552, 0.0, 118.4615),  # Checkpoint 7
    (147.7148, 0.0, 100.3988),  # Alignment vector
    (121.4415, 0.0, 96.3562),  # Checkpoint 8
    (113.6536, 0.0, 113.976),  # Alignment vector
    (119.7501, 0.0, 126.09),  # Checkpoint 9
    (127.0356, 0.0, 129.3163),  # Alignment vector
    (124.6458, 0.0, 137.3901),  # Alignment vector
    (124.3621, 0.0, 144.1631),  # Alignment vector
    (112.2867, 0.0, 194.0876),  # Checkpoint 10
    (94.5945, 0.0, 195.8559),  # Alignment vector
    (86.3372, 0.0, 195.8754),  # Alignment vector
    (75.7412, 0.0, 208.8779),  # Checkpoint 11
    (60.3128, 0.0, 208.8806)  # Checkpoint 12
]


# ClientPos
# P        0 +  1 =   1
# Secret   1 +  8 =   9
# Time     9 +  8 =  17
# Pos     17 + 12 =  29
# Angle   29 + 12 =  41
# Garbage 41 +  5 = 46

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


def list_npcs(global_data, **kwargs):
    for uid in global_data['npcs']:
        print(f'{uid}: {global_data["npcs"][uid]}')


def track_npc(command, global_data, **kwargs):
    if len(command) < 2:
        print(f'Usage: {command[0]} [uid]; uid 0 = off')
        return

    uid = int(command[1])
    global_data['tracked_player'] = uid

    if uid == 0:
        print('Tracking disabled')
    else:
        name = global_data['npcs'][uid] if uid in global_data['npcs'] else f'<Unknown: {uid}>'
        print(f'Tracking: {name}')


def plot_npc(global_data, **kwargs):
    tracked = global_data.get('tracked_player', 0)
    if tracked == 0:
        return

    data = global_data['tracking_data'][tracked]
    x, z = zip(*data)
    plt.plot(x, z, 'o')
    plt.show()


COMMANDS = {
    'emote': send_emote,
    'getpos': get_position,
    'up': teleport_up,
    'vhover': virtual_hover,
    'sc': show_checkpoint,
    'race': race,
    'npcs': list_npcs,
    'track': track_npc,
    'plot': plot_npc
}
