import sys,os
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server

def test_parse():
    m=server.parse_mqtt("factory/line1/cmd/valve",'{"open":true}',1,False)
    assert m.is_command; assert m.payload_kind=="json"
def test_govern():
    g=server.govern_iot("factory/line1/cmd/valve","{}",0,False,tls=False,authenticated=False)
    assert any("62443" in x for x in g.frameworks); assert g.risk_flags
