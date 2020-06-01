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
