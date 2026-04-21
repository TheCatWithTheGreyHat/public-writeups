def lfsr_update(current, param):
    val = current & 0xFFFF
    new_val = (((val >> 5 ^ val >> 2 ^ val ^ val >> 3) << 15) | (val >> 1)) ^ param
    return new_val & 0xFFFF

TARGET = 59038   # 0xe69e
LFSR_INIT = 0xD3AD

from collections import deque

start_lfsr = lfsr_update(LFSR_INIT, 1)
queue = deque()
# Stato: (lfsr, path, sintonizzato_su_666)
# All'avvio non siamo sintonizzati su nulla → False
queue.append((start_lfsr, [1], False))

MAX_DEPTH = 20
found = []
visited = set()

while queue:
    current_lfsr, path, tuned_666 = queue.popleft()

    if len(path) > MAX_DEPTH:
        continue

    state = (current_lfsr, tuned_666, len(path))
    if state in visited:
        continue
    visited.add(state)

    for next_action in [2, 3]:  # 2=SCAN, 3=TUNE
        new_lfsr = lfsr_update(current_lfsr, next_action)
        new_path = path + [next_action]

        if next_action == 3:
            # Il TUNE aggiorna sempre la stazione a 666 (è l'unica scelta valida)
            new_tuned = True
        else:
            new_tuned = tuned_666  # SCAN non cambia la stazione

        # Condizione vincente: lfsr giusto + TUNE + sintonizzati su 666
        if new_lfsr == TARGET and next_action == 3 and new_tuned:
            found.append(new_path)
            action_names = {1: 'ON', 2: 'SCAN', 3: 'TUNE(666)'}
            readable = ' → '.join(action_names[a] for a in new_path)
            print(f"TROVATO! Path: {readable}")
            print(f"LFSR finale: {new_lfsr} (0x{new_lfsr:04x})")
            break

        queue.append((new_lfsr, new_path, new_tuned))

    if found:
        break

if not found:
    print("Nessuna sequenza trovata entro la profondità massima.")