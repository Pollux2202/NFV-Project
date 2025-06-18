import topology


def ping(client, server, expected: bool, count: int = 1, wait: int = 1) -> bool:

    server_ip = server.IP()
    cmd = f"ping {server_ip} -c {count} -W {wait} >/dev/null 2>&1; echo $?"
    ret = client.cmd(cmd).strip()

    try:
        result_code = int(ret)
    except ValueError:
        print(f"Invalid ping result '{ret}' from {client.name}")
        return False

    success = (result_code == 0)
    
    if success == expected:
        print(f"[PASS] {client.name} ping {server.name} → {'Success' if success else 'Failure'} as expected.")
        return True
    else:
        print(f"[FAIL] {client.name} ping {server.name} → {'Success' if success else 'Failure'}, but expected {'Success' if expected else 'Failure'}.")
        return False

def curl(client, server, method="GET", payload="", port=80, expected=True) -> bool:
    # Determine server IP
    if not isinstance(server, str):
        server_ip = server.IP()
        server_name = server.name
    else:
        server_ip = server
        server_name = server  # Just show IP in print if no Mininet host

    # Escape payload to avoid shell issues (basic level)
    safe_payload = payload.replace("'", "'\"'\"'")  # escape single quote for shell

    # Build curl command
    cmd = (
        f"curl --connect-timeout 3 --max-time 3 "
        f"-X {method} -d '{safe_payload}' -s {server_ip}:{port} > /dev/null 2>&1; echo $?"
    )

    # Run command
    ret = client.cmd(cmd).strip()

    try:
        result_code = int(ret)
    except ValueError:
        print(f"[ERROR] Invalid curl return code '{ret}' from {client.name}")
        return False

    success = (result_code == 0)

    # Result matching
    if success == expected:
        print(f"[PASS] {client.name} → {method} {server_name}:{port} → {'Success' if success else 'Failure'} as expected.")
        return True
    else:
        print(f"[FAIL] {client.name} → {method} {server_name}:{port} → {'Success' if success else 'Failure'}, expected {'Success' if expected else 'Failure'}.")
        return False


