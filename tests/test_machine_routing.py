"""Machine routing endpoints on the Alerts page: access control."""
from conftest import login, make_user


def test_non_admin_cannot_read_other_machines_rules(client):
    make_user(2, "viewer")
    login(client, "viewer")  # allowed_servers() is empty for non-admins in tests
    assert client.get("/alerts/machine/machine_other/overrides").status_code == 403


def test_non_admin_cannot_save_or_reset(client):
    make_user(2, "viewer")
    login(client, "viewer")
    assert client.post("/alerts/machine/machine_x/save-all").status_code == 403
    assert client.post("/alerts/machine/machine_x/reset").status_code == 403
