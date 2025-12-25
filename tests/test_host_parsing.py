import main

def test_classify_ipv4():
    res = main.classify_asset("192.168.1.1")
    assert res == ("IPv4", "", "192.168.1.1")

def test_classify_hostname():
    res = main.classify_asset("server-01.local")
    assert res == ("Hostname", "server-01.local", "")

def test_classify_unknown():
    # User@1.2.3.4 is now valid! Let's use a real unknown.
    res = main.classify_asset("Invalid@Invalid")
    assert res == ("Unknown", "Invalid@Invalid", "")

def test_normalize_input():
    raw = "a,b\nc,  d  ,,e"
    # 1. \n -> , : "a,b,c,  d  ,,e"
    # 2. Split , : ["a", "b", "c", "  d  ", "", "e"]
    # 3. Trim : ["a", "b", "c", "d", "", "e"]
    # 4. Remove Empty : ["a", "b", "c", "d", "e"]
    # 5. Dedupe
    
    res = main.normalize_input_v12(raw)
    assert res == ["a", "b", "c", "d", "e"]
    
def test_normalize_dedupe():
    raw = "a,b,a,c"
    res = main.normalize_input_v12(raw)
    assert res == ["a", "b", "c"]

def test_classify_composite_at():
    # User@IP (Standard)
    res = main.classify_asset("User@10.1.50.162")
    assert res == ("Derived", "User", "10.1.50.162")

    # Spaces around @
    res = main.classify_asset("ForeScoutCounterACT @ 10.240.240.65")
    assert res == ("Derived", "ForeScoutCounterACT", "10.240.240.65")

    # Spaces in Hostname
    res = main.classify_asset("My Server Name @ 1.2.3.4")
    assert res == ("Derived", "My Server Name", "1.2.3.4")

def test_classify_composite_paren():
    # User (IP)
    res = main.classify_asset("Server (192.168.0.1)")
    assert res == ("Derived", "Server", "192.168.0.1")

    # Spaces inside parens
    res = main.classify_asset("Server ( 192.168.0.1 )")
    assert res == ("Derived", "Server", "192.168.0.1")

def test_classify_composite_space():
    # Host IP (Space Separated)
    res = main.classify_asset("FinPreProd 10.73.2.11")
    assert res == ("Derived", "FinPreProd", "10.73.2.11")

    # Host IP (Multiple Spaces)
    res = main.classify_asset("MyServer    192.168.1.5")
    assert res == ("Derived", "MyServer", "192.168.1.5")
    
    # Validation: Should not match just IP
    res = main.classify_asset("192.168.1.1")
    assert res == ("IPv4", "", "192.168.1.1")
