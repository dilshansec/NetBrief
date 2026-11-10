from pathlib import Path
from fastapi.testclient import TestClient
from netsentry.main import app
from netsentry.parser import analyze, CaptureError

ROOT=Path(__file__).resolve().parents[1]
client=TestClient(app)

def test_health():
    assert client.get('/api/health').json()['status']=='ok'

def test_demo_analysis():
    data=(ROOT/'samples'/'demo_scan.pcap').read_bytes()
    result=analyze(data,'demo_scan.pcap')
    assert result['summary']['packets']==25
    assert result['protocols']['TCP']==25
    assert len(result['alerts'])==1
    assert '25 unique' in result['alerts'][0]['evidence']

def test_upload():
    data=(ROOT/'samples'/'demo_scan.pcap').read_bytes()
    res=client.post('/api/analyze',files={'file':('demo_scan.pcap',data,'application/octet-stream')})
    assert res.status_code==200
    assert res.json()['summary']['packets']==25

def test_invalid():
    res=client.post('/api/analyze',files={'file':('bad.pcap',b'not a pcap')})
    assert res.status_code==400

def test_index():
    assert 'NetSentry' in client.get('/').text
