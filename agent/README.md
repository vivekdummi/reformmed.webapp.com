# Reformmed Monitor Agent

Runs on each monitored Linux machine and posts metrics to the ingest API
(`server/main.py`) every `REFORMMED_INTERVAL` seconds. Installed at
`/opt/reformmed-agent/agent.py` with its own `venv` and `.env`.

## Update on a server

```bash
sudo cp /opt/reformmed-agent/agent.py /opt/reformmed-agent/agent.py.bak
# copy the new agent.py to /opt/reformmed-agent/agent.py, then:
sudo /opt/reformmed-agent/venv/bin/python -m py_compile /opt/reformmed-agent/agent.py && echo OK
systemctl list-units --type=service | grep -i -E "reformmed|agent"   # find the service name
sudo systemctl restart <service>
sudo journalctl -u <service> -n 30 --no-pager
```

Roll back: copy `agent.py.bak` back over `agent.py` and restart.

## PM2

The agent reports every PM2 daemon on the machine (one per user that
started PM2, e.g. root's `/root/.pm2` and a user's `~/.pm2`), querying each
as its owner. **Run the agent as root** to see all of them; as a normal user
it only reports that user's own PM2 and logs a warning for the rest.

A healthy start logs:

```
Run as   : root
✅ PM2 daemons: root (/root/.pm2), adminqa (/home/adminqa/.pm2)
📊 1 sent | ... | PM2: 28(0 down) [adminqa, root]
```

## `.env`

| Variable | Meaning |
|---|---|
| `REFORMMED_API_URL` | Ingest API base URL |
| `REFORMMED_API_SECRET` | API key (`X-API-Key`) |
| `REFORMMED_SYSTEM_NAME` | Machine name shown in the dashboard |
| `REFORMMED_LOCATION` | Location shown in the dashboard |
| `REFORMMED_INTERVAL` | Seconds between reports (default 15) |
