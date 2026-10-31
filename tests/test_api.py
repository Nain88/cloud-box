import json
import pytest
from fastapi.testclient import TestClient
from cbb.api import create_app
from cbb.config import Settings
from cbb.crypto import now


@pytest.fixture
def app_client(tmp_path):
    app=create_app(Settings(data=tmp_path,workers=False))
    with TestClient(app) as client:
        token=app.state.service.bootstrap_file.read_text()
        assert client.post("/api/v1/admin/setup",json={"token":token,"username":"test-admin","password":"valid-test-password-123"}).status_code==200
        login=client.post("/api/v1/auth/session",json={"username":"test-admin","password":"valid-test-password-123"}).json()
        client.headers["x-csrf-token"]=login["csrf"]
        yield app,client
    app.state.service.db.engine.dispose()


def test_sessions_csrf_and_origin(app_client):
    app,c=app_client
    assert c.get("/api/v1/overview").json()["cases"]==1
    assert c.post("/api/v1/enrollments",json={},headers={"x-csrf-token":"wrong"}).status_code==403
    assert c.post("/api/v1/enrollments",json={},headers={"origin":"https://evil.example"}).status_code==403
    assert c.post("/api/v1/enrollments",content='{"name":"a","name":"b"}',headers={"content-type":"application/json"}).status_code==400
    assert c.delete("/api/v1/auth/session").status_code==200
    assert c.get("/api/v1/evidence").status_code==401


def test_case_scope_optimistic_concurrency_and_reviewer(app_client):
    app,c=app_client
    case=c.get("/api/v1/cases").json()[0]
    response=c.post("/api/v1/users",json={"username":"review-user","password":"valid-review-password","role":"reviewer"})
    assert response.status_code==200
    reviewer_id=response.json()["id"]
    assert c.patch("/api/v1/cases/"+case["id"],json={"version":0,"title":"stale"}).status_code==409
    assert c.post("/api/v1/cases/"+case["id"]+"/members",json={"user_id":reviewer_id}).status_code==200
    with TestClient(app) as r:
        auth=r.post("/api/v1/auth/session",json={"username":"review-user","password":"valid-review-password"}).json();r.headers["x-csrf-token"]=auth["csrf"]
        assert len(r.get("/api/v1/cases").json())==1
        assert r.post("/api/v1/cases",json={"title":"not allowed"}).status_code==403
        assert r.post("/api/v1/cases/"+case["id"]+"/notes",json={"body":"Reviewed"}).status_code==200
        assert c.delete("/api/v1/cases/"+case["id"]+"/members/"+reviewer_id).status_code==200
        assert r.get("/api/v1/cases/"+case["id"]).status_code==404


def test_single_use_enrollment_and_revocation(app_client):
    app,c=app_client
    token=c.post("/api/v1/enrollments",json={"name":"fixture","os":"fixture"}).json()["token"]
    enrolled=c.post("/api/v1/collectors/enroll",json={"token":token}).json()
    assert c.post("/api/v1/collectors/enroll",json={"token":token}).status_code==403
    headers={"authorization":"Bearer "+enrolled["token"]}
    assert c.post("/api/v1/collectors/heartbeat",json={"uptime":1},headers=headers).status_code==200
    assert c.post("/api/v1/collectors/"+enrolled["collector_id"]+"/revoke",json={}).status_code==200
    assert c.post("/api/v1/collectors/heartbeat",json={},headers=headers).status_code==401


def test_cloud_refuses_insecure_defaults(tmp_path):
    with pytest.raises(ValueError,match="PostgreSQL"):Settings(data=tmp_path,mode="cloud").prepare()


def test_saved_views_are_private_and_versioned(app_client):
    app,c=app_client
    assert c.get("/api/v1/saved-views").json()=={"version":0,"views":[]}
    assert c.put("/api/v1/saved-views",json={"version":0,"views":[{"name":"Network","source":"suricata.eve"}]}).status_code==200
    assert c.put("/api/v1/saved-views",json={"version":0,"views":[]}).status_code==409
