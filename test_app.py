from fastapi.testclient import TestClient
from app import app

client = TestClient(app)


def test_valid_production_promotion():
    payload = {
        "target": "production",
        "event": "push",
        "ref": "refs/heads/main",
        "workflow": {
            "trigger": "push",
            "permissions": {
                "contents": "read",
                "packages": "write",
                "id-token": "none",
            },
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "environmentApproval": True,
            "actions": [{"owner": "actions", "name": "checkout", "ref": "v4"}],
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "buildkit",
            "criticalVulnerabilities": 0,
            "digestPinned": True,
        },
    }
    response = client.post("/release-gate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "promote"
    assert data["violations"] == []