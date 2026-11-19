import asyncio
import io
import json
from unittest.mock import patch
import pytest
from fastapi import UploadFile, HTTPException
from fastapi.testclient import TestClient
import netsentry.main as api
from samples.lab import generate

@pytest.fixture(autouse=True)
def clean():
    api.requests.clear();api.reports.clear()
    yield
    api.requests.clear();api.reports.clear()

client=TestClient(api.app)
def submit(name='normal',settings=None):
    return client.post('/api/analyze',files={'file':(name+'.pcap',generate(name))},data={'settings':json.dumps(settings or {})})

def test_paginated_isolated_results():
    a=submit('port_scan').json();b=submit().json()
    assert a['analysis_id']!=b['analysis_id']
    url=f"/api/analyses/{a['analysis_id']}/packets"
    assert client.get(url).status_code==404
    assert client.get(url,headers={'Authorization':'Bearer '+b['access_token']}).status_code==404
    h={'Authorization':'Bearer '+a['access_token']}
    r=client.get(url+'?limit=5&offset=5',headers=h).json()
    assert r['total']==30 and len(r['items'])==5 and r['items'][0]['no']==6
    assert client.get(url+'?limit=1001',headers=h).status_code==422
    evidence=client.get(f"/api/analyses/{a['analysis_id']}/alerts/{a['alerts'][0]['id']}/evidence",headers=h).json()
    assert len(evidence['packets'])==30
    assert a['packets']==[]

def test_configuration_and_upload_validation():
    assert submit(settings={'scan_ports':0}).status_code==422
    assert client.post('/api/analyze',files={'file':('bad.exe',b'bad')}).status_code==400
    assert client.post('/api/analyze',files={'file':('bad.pcap',b'bad')}).status_code==400
    with patch.object(api,'MAX_UPLOAD',20):assert submit().status_code==413
    assert client.post('/api/analyze',headers={'Origin':'https://untrusted.test'},files={'file':('x.pcap',generate('normal'))}).status_code==403

def test_expiry_and_capacity():
    r=submit().json();identifier=r['analysis_id'];ts,token,data=api.reports[identifier]
    api.reports[identifier]=(ts-api.TTL-1,token,data)
    assert client.get(f'/api/analyses/{identifier}/summary',headers={'Authorization':'Bearer '+token}).status_code==404
    for _ in range(5):assert submit().status_code==200
    assert len(api.reports)==4

def test_concurrency_gate_and_file_cleanup():
    f=UploadFile(filename='normal.pcap',file=io.BytesIO(generate('normal')))
    async def run():
        with patch.object(api,'active',1):
            with pytest.raises(HTTPException) as exc:await api.upload(f,'{}',False)
            assert exc.value.status_code==429
    asyncio.run(run());assert f.file.closed

def test_rate_limit():
    api.requests.extend([api.time.monotonic()]*20)
    assert submit().status_code==429

def test_failure_file_cleanup():
    f=UploadFile(filename='bad.pcap',file=io.BytesIO(b'bad'))
    async def run():
        with pytest.raises(HTTPException):await api.upload(f,'{}',False)
    asyncio.run(run());assert f.file.closed

def test_sample_allowlist():
    assert client.get('/sample/lab/missing').status_code==404
    assert client.get('/sample/lab/normal').content[:4]==b'\xd4\xc3\xb2\xa1'

def test_worker_timeout_kills_process_and_closes_upload():
    from unittest.mock import AsyncMock
    class Worker:
        returncode=None
        killed=False
        communicate=AsyncMock(side_effect=asyncio.TimeoutError)
        async def wait(self):self.returncode=-1
        def kill(self):self.killed=True
    worker=Worker()
    f=UploadFile(filename='normal.pcap',file=io.BytesIO(generate('normal')))
    async def run():
        with patch.object(api.asyncio,'create_subprocess_exec',AsyncMock(return_value=worker)):
            with pytest.raises(HTTPException) as exc:await api.upload(f,'{}',False)
            assert exc.value.status_code==408
    asyncio.run(run())
    assert worker.killed and f.file.closed and api.active==0

def test_offline_api_documentation():
    assert 'API' in client.get('/api/docs').text
    assert client.get('/openapi.json').status_code==200
