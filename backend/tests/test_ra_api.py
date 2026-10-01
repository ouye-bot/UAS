"""RA API 测试（B2）：四端点正例+负例三连 HTTP 语义（fake 链锚注入）。

DB=独立临时 sqlite 文件（API 层走 app.db.get_session 依赖）。
"""

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["FZ_CHAIN_ANCHOR"] = "fake"
os.environ["FZ_DB_PATH_OVERRIDE"] = str(Path(__file__).parent / ".test_ra_api.db")

import app.db as db_mod  # noqa: E402
from app.main import create_app  # noqa: E402
from app.ra import router as ra_router  # noqa: E402
from app.ra.models import Base  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_file = tmp_path / "ra_api_test.db"
    monkeypatch.setattr(db_mod, "_DB_PATH", db_file)
    engine = db_mod.create_engine(f"sqlite:///{db_file}")
    db_mod._engine = engine
    db_mod.SessionLocal = db_mod.sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    ra_router._reset_deps_cache()
    with TestClient(create_app()) as c:
        from tests.accounting import register_and_login

        register_and_login(c, "admin_ra", "admin", "Admin-Pass-1")
        yield c
    ra_router._reset_deps_cache()


def _pub() -> str:
    from app.crypto.sm2 import generate_keypair

    return generate_keypair()[1]


def _register(client, username="api-pilot"):
    r = client.post(
        "/ra/register",
        json={
            "username": username,
            "id_number": "11010119900307999X",
            "cert_level": 3,
            "sn": "UAS-SN-2026-0001",
            "user_pub_hex": _pub(),
        },
    )
    assert r.status_code == 200, r.text
    return r.json()["data"]


def test_healthz(client):
    assert client.get("/ra/healthz").json() == {"service": "ra", "ok": True}


def test_register_and_chain_fake_calls(client):
    reg = _register(client)
    assert len(reg["message_hex"]) == 330
    fake = ra_router._ra_deps().anchor.call
    assert ("register_commitment", ["0x" + reg["master_cred_hash_hex"], 1]) in fake.calls


def test_sub_credentials_positive(client):
    reg = _register(client, "api-pilot2")
    r = client.post(
        "/ra/sub-credentials",
        json={
            "master_cred_hash_hex": reg["master_cred_hash_hex"],
            "salt_hex": reg["salt_hex"],
            "id_number": "11010119900307999X",
            "cert_level": 3,
            "sn": "UAS-SN-2026-0001",
            "holder_pub_hex": _pub(),
        },
    )
    assert r.status_code == 200, r.text
    data = r.json()["data"]
    assert len(data["message_hex"]) == 330 and len(data["sig_hex"]) == 128


def test_sub_credentials_negative_revoked(client):
    reg = _register(client, "api-rev")
    assert (
        client.post(
            "/ra/revoke",
            
            json={"master_cred_hash_hex": reg["master_cred_hash_hex"], "reason": "违规"},
        ).status_code
        == 200
    )
    r = client.post(
        "/ra/sub-credentials",
        json={
            "master_cred_hash_hex": reg["master_cred_hash_hex"],
            "salt_hex": reg["salt_hex"],
            "id_number": "11010119900307999X",
            "cert_level": 3,
            "sn": "UAS-SN-2026-0001",
            "holder_pub_hex": _pub(),
        },
    )
    assert r.status_code == 403
    assert r.json()["code"] == "cred_revoked"


def test_sub_credentials_negative_bad_preimage(client):
    reg = _register(client, "api-bad")
    r = client.post(
        "/ra/sub-credentials",
        json={
            "master_cred_hash_hex": reg["master_cred_hash_hex"],
            "salt_hex": "00" * 16,
            "id_number": "11010119900307999X",
            "cert_level": 3,
            "sn": "UAS-SN-2026-0001",
            "holder_pub_hex": _pub(),
        },
    )
    assert r.status_code == 403
    assert r.json()["code"] == "bad_preimage"


def test_snapshot_public(client):
    reg = _register(client, "api-snap")
    client.post(
        "/ra/revoke",
        json={"master_cred_hash_hex": reg["master_cred_hash_hex"]},
        
    )
    r = client.get("/ra/revocation/snapshot")
    assert r.status_code == 200
    data = r.json()["data"]
    assert data["epoch"] == 1 and len(data["root_hex"]) == 64
    assert reg["master_cred_hash_hex"] in data["revoked_handles_hex"]
