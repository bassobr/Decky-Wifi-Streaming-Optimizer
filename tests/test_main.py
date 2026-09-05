"""Backend unit tests. Run with `python3 -m pytest tests/ -q` from the repo
root. The wifioptimizer package falls back to a decky stub when the real
module is absent, so these tests run on any machine; everything that would
touch the system goes through monkeypatched _run_cmd/_get_wifi_interface."""

import asyncio
import io
import json
import os
import subprocess
import sys
import tarfile
import zipfile

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "py_modules"))

import main  # noqa: E402
from wifioptimizer import archives, constants, parsing  # noqa: E402
from wifioptimizer import backend_switch as backend_switch_mod  # noqa: E402
from wifioptimizer import settings as settings_store  # noqa: E402
from wifioptimizer.deckyshim import decky  # noqa: E402


OK_RESULT = {"success": True, "stdout": "", "stderr": "", "returncode": 0}


@pytest.fixture
def settings_env(tmp_path, monkeypatch):
    """Redirect SETTINGS_FILE into a temp dir and reset the cache."""
    settings_file = tmp_path / "settings.json"
    monkeypatch.setattr(settings_store, "SETTINGS_FILE", str(settings_file))
    settings_store._settings_cache["stat"] = None
    settings_store._settings_cache["data"] = None
    yield settings_file
    settings_store._settings_cache["stat"] = None
    settings_store._settings_cache["data"] = None


@pytest.fixture
def plugin():
    return main.Plugin()


# ---- settings load/save ----

def test_load_settings_missing_returns_defaults(settings_env):
    settings = settings_store.load_settings()
    assert settings == constants.DEFAULT_SETTINGS
    assert settings is not constants.DEFAULT_SETTINGS
    assert settings["streaming_apps"] is not constants.DEFAULT_SETTINGS["streaming_apps"]


def test_load_settings_merges_defaults_and_strips_stale(settings_env):
    settings_env.write_text(json.dumps({
        "power_save_disabled": False,
        "stale_key_from_old_version": 1,
        "streaming_apps": {"moonlight": False, "removed_app": True},
    }))
    settings = settings_store.load_settings()
    assert settings["power_save_disabled"] is False
    assert "stale_key_from_old_version" not in settings
    # per-app merge: user choice kept, new presets default to enabled
    assert settings["streaming_apps"]["moonlight"] is False
    assert settings["streaming_apps"]["chiaki"] is True
    assert "removed_app" not in settings["streaming_apps"]
    # snapshot keys from DEFAULT_SETTINGS appear
    assert settings["sysctl_snapshot"] == {}


@pytest.mark.parametrize("content", ["{not json", json.dumps([1, 2, 3])])
def test_load_settings_corrupt_backs_up_file(settings_env, content):
    settings_env.write_text(content)
    settings = settings_store.load_settings()
    assert settings == constants.DEFAULT_SETTINGS
    assert not settings_env.exists()
    corrupt = settings_env.parent / "settings.json.corrupt"
    assert corrupt.exists()
    assert corrupt.read_text() == content


def test_save_and_reload_roundtrip(settings_env):
    settings = settings_store.load_settings()
    settings["dns_enabled"] = True
    settings["dns_servers"] = "9.9.9.9"
    settings_store.save_settings(settings)
    reloaded = settings_store.load_settings()
    assert reloaded["dns_enabled"] is True
    assert reloaded["dns_servers"] == "9.9.9.9"


def test_save_settings_ignores_planted_tmp_symlink(settings_env, tmp_path):
    # SEC-01: a symlink planted at settings.json.tmp must not redirect the
    # write; the symlink is unlinked, never followed.
    target = tmp_path / "victim.txt"
    target.write_text("precious")
    os.symlink(target, settings_env.parent / "settings.json.tmp")
    settings_store.save_settings(dict(constants.DEFAULT_SETTINGS))
    assert target.read_text() == "precious"
    assert json.loads(settings_env.read_text())["driver"] == "unknown"


def test_save_settings_replaces_symlinked_settings_file(settings_env, tmp_path):
    # SEC-01: rename-over must replace the symlink itself, not its target.
    target = tmp_path / "victim2.txt"
    target.write_text("precious")
    os.symlink(target, settings_env)
    settings_store.save_settings(dict(constants.DEFAULT_SETTINGS))
    assert target.read_text() == "precious"
    assert not settings_env.is_symlink()


def test_save_settings_refuses_symlinked_settings_dir(tmp_path, monkeypatch):
    # SEC-01: the whole settings dir swapped for a symlink is refused.
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link_dir = tmp_path / "linked"
    os.symlink(real_dir, link_dir)
    monkeypatch.setattr(settings_store, "SETTINGS_FILE", str(link_dir / "settings.json"))
    settings_store._settings_cache["stat"] = None
    settings_store._settings_cache["data"] = None
    with pytest.raises(OSError):
        settings_store.save_settings(dict(constants.DEFAULT_SETTINGS))


def test_update_settings_fields_is_isolated(settings_env):
    settings_store.save_settings(dict(constants.DEFAULT_SETTINGS))
    settings_store.update_settings_fields(last_connection_uuid="abc", priority_set=True)
    settings = settings_store.load_settings()
    assert settings["last_connection_uuid"] == "abc"
    assert settings["priority_set"] is True
    assert settings["power_save_disabled"] is True  # untouched


# ---- volatile gate ----

@pytest.mark.parametrize(
    "mode,active,expected",
    [(False, False, True), (False, True, True), (True, False, False), (True, True, True)],
)
def test_volatile_gate(plugin, mode, active, expected):
    settings = {"streaming_mode_enabled": mode, "streaming_active": active}
    assert plugin._volatile_gate_open(settings) is expected


# ---- streaming patterns ----

def test_build_patterns_presets_and_custom():
    settings = {
        "streaming_apps": {"moonlight": True, "chiaki": False},
        "streaming_custom_patterns": "MyApp, xx yzapp",
    }
    patterns = parsing.build_patterns(settings)
    flat = [p for p, _ in patterns]
    assert "moonlight" in flat
    assert "chiaki" not in flat  # disabled preset
    assert "myapp" in flat  # lowered
    assert "yzapp" in flat
    assert "xx" not in flat  # below MIN_PATTERN_LEN


def test_set_streaming_custom_patterns_rejects_short(settings_env, plugin):
    result = asyncio.run(plugin.set_streaming_custom_patterns("ok-pattern ab"))
    assert result["success"] is False
    assert "ab" in result["message"]
    # nothing persisted
    assert settings_store.load_settings()["streaming_custom_patterns"] == ""


def test_set_streaming_custom_patterns_accepts_valid(settings_env, plugin):
    result = asyncio.run(plugin.set_streaming_custom_patterns("  vortex, gamehub  "))
    assert result["success"] is True
    assert settings_store.load_settings()["streaming_custom_patterns"] == "vortex, gamehub"


# ---- update check / verification ----

def _fake_github(monkeypatch, plugin, payload: dict):
    def fake_run_cmd(cmd, timeout=5, clean_env=False):
        return {**OK_RESULT, "stdout": json.dumps(payload)}
    monkeypatch.setattr(plugin, "_run_cmd", fake_run_cmd)


@pytest.mark.parametrize(
    "current,tag,expected",
    [
        ("0.12.2", "v0.13.0", True),
        ("0.12.2", "v0.12.2", False),
        ("0.13.0", "v0.12.2", False),
        ("0.12.10", "v0.12.9", False),   # tuple compare, not string compare
        ("0.12.2-beta", "v0.12.2", True),  # beta user moves back to stable
    ],
)
def test_check_for_update_stable(settings_env, plugin, monkeypatch, current, tag, expected):
    monkeypatch.setattr(decky, "DECKY_PLUGIN_VERSION", current)
    _fake_github(monkeypatch, plugin, {"tag_name": tag})
    result = asyncio.run(plugin.check_for_update())
    assert result["success"] is True
    assert result["update_available"] is expected


def test_check_for_update_beta_differs(settings_env, plugin, monkeypatch):
    settings = settings_store.load_settings()
    settings["update_channel"] = "beta"
    settings_store.save_settings(settings)
    monkeypatch.setattr(decky, "DECKY_PLUGIN_VERSION", "0.12.2")
    _fake_github(monkeypatch, plugin, {"version": "0.12.3-beta"})
    result = asyncio.run(plugin.check_for_update())
    assert result["update_available"] is True


def test_apply_update_rejects_bad_version(settings_env, plugin, monkeypatch):
    async def fake_check():
        return {"update_available": True, "channel": "stable",
                "latest_version": "0.1.0$(reboot)"}
    monkeypatch.setattr(plugin, "check_for_update", fake_check)
    result = asyncio.run(plugin.apply_update())
    assert result["success"] is False
    assert "version string" in result["message"]


def test_update_handoff_script_copies_py_modules(plugin):
    # The modularized backend must survive updates: the hand-off script has
    # to copy py_modules/ content, not just the historic fixed file list.
    assert 'cp -r "$WIFIOPT_SRC/py_modules/."' in plugin._UPDATE_HANDOFF_SCRIPT


def test_verify_sha256(tmp_path):
    f = tmp_path / "a.zip"
    f.write_bytes(b"hello world")
    import hashlib
    digest = hashlib.sha256(b"hello world").hexdigest()
    ok, _ = archives.verify_sha256(f"{digest}  a.zip\n", "a.zip", str(f))
    assert ok
    ok, _ = archives.verify_sha256(f"{digest} *a.zip\n", "a.zip", str(f))  # binary marker
    assert ok
    ok, detail = archives.verify_sha256(f"{'0' * 64}  a.zip\n", "a.zip", str(f))
    assert not ok and "mismatch" in detail
    ok, detail = archives.verify_sha256(f"{digest}  other.zip\n", "a.zip", str(f))
    assert not ok and "no entry" in detail


def test_safe_extract_zip_rejects_traversal(tmp_path):
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("../escape.txt", "boom")
    with pytest.raises(ValueError):
        archives.safe_extract_zip(str(evil), str(tmp_path / "out"))

    good = tmp_path / "good.zip"
    with zipfile.ZipFile(good, "w") as z:
        z.writestr("Plugin/plugin.json", "{}")
    archives.safe_extract_zip(str(good), str(tmp_path / "out2"))
    assert (tmp_path / "out2" / "Plugin" / "plugin.json").exists()


def _make_tar(path, member_name, mode=None, linkname=None):
    with tarfile.open(path, "w:gz") as t:
        data = b"boom"
        info = tarfile.TarInfo(member_name)
        if linkname:
            info.type = tarfile.SYMTYPE
            info.linkname = linkname
            t.addfile(info)
        else:
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))


def test_safe_extract_tar_rejects_traversal(tmp_path):
    evil = tmp_path / "evil.tar.gz"
    _make_tar(evil, "../escape.txt")
    with pytest.raises(Exception):
        archives.safe_extract_tar(str(evil), str(tmp_path / "out"))
    assert not (tmp_path / "escape.txt").exists()

    good = tmp_path / "good.tar.gz"
    _make_tar(good, "repo-beta/plugin.json")
    archives.safe_extract_tar(str(good), str(tmp_path / "out2"))
    assert (tmp_path / "out2" / "repo-beta" / "plugin.json").exists()


# ---- parsers ----

IW_LINK_OUT = """Connected to aa:bb:cc:dd:ee:ff (on wlan0)
\tSSID: MyNet
\tfreq: 5180
\tRX: 123 bytes (4 packets)
\tTX: 456 bytes (5 packets)
\tsignal: -52 dBm
\ttx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2
"""


def test_parse_iw_link():
    info = parsing.parse_iw_link(IW_LINK_OUT)
    assert info["signal_dbm"] == "-52 dBm"
    assert info["tx_bitrate"].startswith("866.7 MBit/s")
    assert info["frequency"] == "5180"
    assert parsing.parse_iw_link("") == {}


def test_parse_iw_channel():
    out = "Interface wlan0\n\tchannel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz\n"
    assert parsing.parse_iw_channel(out) == "36 (80 MHz)"
    assert parsing.parse_iw_channel("channel 6 (2437 MHz)") == "6"
    assert parsing.parse_iw_channel("no channel here") is None


def test_parse_nmcli_fields():
    out = (
        "802-11-wireless.bssid:AA\\:BB\\:CC\\:DD\\:EE\\:FF\n"
        "ipv6.method:disabled\n"
        "802-11-wireless.band:a\n"
        "IP4.ADDRESS[1]:192.168.1.50/24\n"
        "IP4.DNS[1]:1.1.1.1\n"
        "IP4.DNS[2]:1.0.0.1\n"
    )
    fields = parsing.parse_nmcli_fields(out)
    assert fields["802-11-wireless.bssid"] == ["AA:BB:CC:DD:EE:FF"]
    assert fields["ipv6.method"] == ["disabled"]
    assert fields["IP4.DNS"] == ["1.1.1.1", "1.0.0.1"]
    assert fields["IP4.ADDRESS"] == ["192.168.1.50/24"]


def test_dns_drifted():
    assert parsing.dns_drifted("1.1.1.1 1.0.0.1", ["1.1.1.1", "1.0.0.1"]) is False
    assert parsing.dns_drifted("1.1.1.1 1.0.0.1", ["192.168.1.1"]) is True
    assert parsing.dns_drifted("", ["192.168.1.1"]) is False
    assert parsing.dns_drifted("1.1.1.1", []) is True


# ---- snapshot / restore ----

def test_txq_off_value(plugin):
    assert plugin._txq_off_value({"txqueuelen_snapshot": ""}) == constants.TXQ_DEFAULT
    assert plugin._txq_off_value({"txqueuelen_snapshot": "1500"}) == "1500"
    # our own tuned values never count as "prior state"
    assert plugin._txq_off_value({"txqueuelen_snapshot": constants.TXQ_TUNED}) == constants.TXQ_DEFAULT
    assert plugin._txq_off_value({"txqueuelen_snapshot": constants.TXQ_CAKE}) == constants.TXQ_DEFAULT


def test_buffer_tuning_restore_prefers_snapshot(settings_env, plugin, monkeypatch):
    settings = settings_store.load_settings()
    settings["sysctl_snapshot"] = {"net.core.rmem_max": "425984"}
    settings_store.save_settings(settings)

    recorded = []

    def fake_run_cmd(cmd, timeout=5, clean_env=False):
        recorded.append(cmd)
        return dict(OK_RESULT)

    monkeypatch.setattr(plugin, "_run_cmd", fake_run_cmd)
    monkeypatch.setattr(plugin, "_get_wifi_interface", lambda: None)

    plugin._apply_buffer_tuning_now(False)

    sysctl_writes = [c[2] for c in recorded if c[:2] == ["/usr/bin/sysctl", "-w"]]
    assert "net.core.rmem_max=425984" in sysctl_writes  # snapshot wins
    assert "net.core.wmem_max=212992" in sysctl_writes  # fallback to default
    # snapshot cleared after restore
    assert settings_store.load_settings()["sysctl_snapshot"] == {}


def test_merge_snapshot_keeps_first_capture(settings_env):
    settings_store.merge_snapshot("pcie_snapshot", {"/sys/x": "1"})
    settings_store.merge_snapshot("pcie_snapshot", {"/sys/x": "0", "/sys/y": "auto"})
    snap = settings_store.load_settings()["pcie_snapshot"]
    assert snap == {"/sys/x": "1", "/sys/y": "auto"}


def test_reset_settings_does_not_share_defaults(settings_env, plugin, monkeypatch):
    monkeypatch.setattr(plugin, "_run_cmd", lambda *a, **k: dict(OK_RESULT))
    monkeypatch.setattr(plugin, "_get_wifi_interface", lambda: None)
    saved = []
    orig_save = settings_store.save_settings
    monkeypatch.setattr(
        settings_store, "save_settings", lambda d: (saved.append(d), orig_save(d))
    )
    result = asyncio.run(plugin.reset_settings())
    assert result["success"] is True
    fresh = saved[-1]
    # FUNC-09: reset must not hand out the module-level defaults dict
    assert fresh["streaming_apps"] is not constants.DEFAULT_SETTINGS["streaming_apps"]
    assert fresh is not constants.DEFAULT_SETTINGS


# ---- backend switch frame ----
#
# The two switch methods (SteamOS helper / generic systemd) share one frame:
# _run_backend_switch owns phases, the reconnect wait, runtime verification,
# and result assembly. A fake step lets us drive every outcome without
# touching the system.

OK_STEP = {
    "failed_early": False,
    "restart_ok": True,
    "detail": "",
    "recovery_performed": False,
    "needs_reboot": False,
}


def _fake_step(outcome):
    async def step(target, other):
        return dict(outcome)
    return step


def _drive_switch(plugin, monkeypatch, outcome, *, final_backend="wpa_supplicant",
                  service_active=True, connected=True):
    monkeypatch.setattr(plugin, "_get_current_backend", lambda: final_backend)
    monkeypatch.setattr(plugin, "_backend_service_active", lambda name: service_active)
    monkeypatch.setattr(
        plugin, "_get_wifi_interface", lambda: "wlan0" if connected else None
    )
    monkeypatch.setattr(
        plugin, "_get_active_connection_uuid", lambda: "uuid-1" if connected else None
    )
    if not connected:
        # The reconnect wait sleeps 15x1s; don't make the test suite pay that.
        async def _no_sleep(_seconds):
            return None
        monkeypatch.setattr(backend_switch_mod.asyncio, "sleep", _no_sleep)
    asyncio.run(
        plugin._run_backend_switch("wpa_supplicant", _fake_step(outcome), "test")
    )
    return plugin._backend_switch


def test_switch_frame_success(plugin, monkeypatch):
    state = _drive_switch(plugin, monkeypatch, OK_STEP)
    assert state["phase"] == "done"
    assert state["in_progress"] is False
    result = state["result"]
    assert result["success"] is True
    assert result["backend"] == "wpa_supplicant"
    assert result["reconnect_timed_out"] is False


def test_switch_frame_failed_early(plugin, monkeypatch):
    outcome = {"failed_early": True, "message": "boom", "detail": "raw stderr"}
    state = _drive_switch(plugin, monkeypatch, outcome)
    assert state["phase"] == "failed"
    assert state["result"]["message"] == "boom"
    assert state["result"]["detail"] == "raw stderr"
    # early failures carry no verification fields
    assert "backend" not in state["result"]


def test_switch_frame_needs_reboot(plugin, monkeypatch):
    outcome = {**OK_STEP, "needs_reboot": True}
    state = _drive_switch(plugin, monkeypatch, outcome)
    result = state["result"]
    assert result["success"] is False
    assert result["needs_reboot"] is True
    assert "wlan0" in result["message"]
    # reconnect wait is skipped on the reboot path
    assert "reconnect_timed_out" not in result


def test_switch_frame_wrong_final_backend(plugin, monkeypatch):
    state = _drive_switch(plugin, monkeypatch, OK_STEP, final_backend="iwd")
    result = state["result"]
    assert result["success"] is False
    assert "Expected wpa_supplicant but got iwd" in result["message"]


def test_switch_frame_service_dead_and_no_reconnect(plugin, monkeypatch):
    state = _drive_switch(
        plugin, monkeypatch, OK_STEP, service_active=False, connected=False
    )
    result = state["result"]
    assert result["success"] is False
    assert result["reconnect_timed_out"] is True
    assert "service isn't running" in result["message"]
    assert result["detail"] == "wpa_supplicant service is not running"


def test_switch_frame_restart_failure_uses_friendly_error(plugin, monkeypatch):
    outcome = {**OK_STEP, "restart_ok": False, "detail": "permission denied"}
    state = _drive_switch(plugin, monkeypatch, outcome)
    result = state["result"]
    assert result["success"] is False
    assert result["message"] == "The system denied permission. Try rebooting."
    assert result["detail"] == "permission denied"


def test_switch_workers_route_through_frame(plugin, monkeypatch):
    async def fake_step(target, other):
        assert other == "wpa_supplicant"  # derived from target inside the frame
        return {"failed_early": True, "message": f"step ran for {target}", "detail": ""}

    monkeypatch.setattr(plugin, "_steamos_switch_step", fake_step)
    asyncio.run(plugin._backend_switch_worker("iwd"))
    assert plugin._backend_switch["result"]["message"] == "step ran for iwd"

    monkeypatch.setattr(plugin, "_generic_switch_step", fake_step)
    asyncio.run(plugin._generic_backend_switch_worker("iwd"))
    assert plugin._backend_switch["result"]["message"] == "step ran for iwd"


# ---- dispatcher rendering ----

def test_render_dispatcher_script(plugin):
    template_path = os.path.join(_ROOT, "defaults", "dispatcher.sh.tmpl")
    with open(template_path) as f:
        template = f.read()
    rendered = plugin._render_dispatcher_script(template)
    for placeholder in ("__SETTINGS_PATH__", "__PLUGIN_DIR__", "__ENFORCED_DIR__",
                        "__SYSCTL_CMDS__", "__DRIVER_FIXES__", "__CAKE_ARGS__",
                        "__TXQ_TUNED__", "__TXQ_CAKE__"):
        assert placeholder not in rendered
    assert "sysctl -w net.core.rmem_max=16777216" in rendered
    assert " ".join(constants.CAKE_QDISC_ARGS) in rendered
    assert '"$DRIVER" = "rtw88"' in rendered
    assert constants.ENFORCED_DIR in rendered
    # an actual eval invocation must never come back (SEC-04); the word may
    # appear in comments explaining exactly that
    for line in rendered.splitlines():
        code = line.split("#", 1)[0].strip()
        assert not code.startswith("eval"), line


def test_rendered_dispatcher_passes_bash_syntax_check(plugin, tmp_path):
    bash = shutil_which("bash")
    if not bash:
        pytest.skip("bash not available")
    template_path = os.path.join(_ROOT, "defaults", "dispatcher.sh.tmpl")
    with open(template_path) as f:
        rendered = plugin._render_dispatcher_script(f.read())
    script = tmp_path / "dispatcher.sh"
    script.write_text(rendered)
    proc = subprocess.run([bash, "-n", str(script)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def shutil_which(name):
    import shutil
    return shutil.which(name)
