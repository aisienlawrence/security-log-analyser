from analyser import get_severity_level, should_flag_ip, analyse_log

#The assert keyword is used when debugging code.

#The assert keyword lets you test if a condition in your code returns True, if not, the program will raise an AssertionError.

failed_attempts = 2
assert failed_attempts == 2
failed_ips = {
    "192.168.1.50": 2,
    "192.168.1.22": 1
}
assert failed_ips == {
    "192.168.1.50": 2,
    "192.168.1.22": 1
}
assert failed_ips["192.168.1.50"] >= 2
assert failed_ips["192.168.1.22"] < 2

def test_should_flag_ip():
    assert not should_flag_ip(1)
    assert should_flag_ip(2)
    assert should_flag_ip(5)
    assert not should_flag_ip(0)
    assert should_flag_ip(6)  

# Test get_severity_level function
def test_get_severity_level():
    assert get_severity_level(1) is None
    assert get_severity_level(2) == "LOW"
    assert get_severity_level(3) == "MEDIUM"
    assert get_severity_level(4) == "HIGH"
    assert get_severity_level(6) == "CRITICAL"
    assert get_severity_level(0) is None
    assert get_severity_level(5) == "HIGH"
    assert get_severity_level(6) == "CRITICAL"
    assert get_severity_level(10) == "CRITICAL"

def test_missing_file(capsys):
    analyse_log("missing_file.log")

    captured = capsys.readouterr()
    assert "File not found" in captured.out

def test_analyse_log_valid_file(tmp_path, capsys):
    log_file = tmp_path / "test.log"
    log_file.write_text(
        "LOGIN SUCCESS user=test ip=10.0.0.1\n"
        "LOGIN FAILED user=test ip=10.0.0.2\n"
        "LOGIN FAILED user=test ip=10.0.0.2\n"
    )

    analyse_log(str(log_file))

    captured = capsys.readouterr()
    assert "TOTAL SUCCESSFUL LOGIN ATTEMPTS: 1" in captured.out
    assert "TOTAL FAILED LOGIN ATTEMPTS: 2" in captured.out
    assert "TOTAL LOGIN ATTEMPTS: 3" in captured.out
    assert "10.0.0.2 has 2 [LOW]" in captured.out

def test_analyse_log_valid_file(tmp_path, capsys):
    log_file = tmp_path / "test.log"
    log_file.write_text(
    "LOGIN SUCCESS user=test ip=10.0.0.1\n"
    "LOGIN FAILED user=test ip=10.0.0.2\n"
    "LOGIN FAILED user=test ip=10.0.0.2\n")

    analyse_log(str(log_file))

    captured = capsys.readouterr()
    assert "TOTAL SUCCESSFUL LOGIN ATTEMPTS: 1" in captured.out
    assert "TOTAL FAILED LOGIN ATTEMPTS: 2" in captured.out
    assert "TOTAL LOGIN ATTEMPTS: 3" in captured.out
    assert "10.0.0.2 has 2 [LOW]" in captured.out

def test_empty_log_file(tmp_path, capsys):
    log_file = tmp_path / "empty.log"
    log_file.write_text("")

    analyse_log(str(log_file))

    captured = capsys.readouterr()
    assert "TOTAL SUCCESSFUL LOGIN ATTEMPTS: 0" in captured.out
    assert "TOTAL FAILED LOGIN ATTEMPTS: 0" in captured.out
    assert "TOTAL LOGIN ATTEMPTS: 0" in captured.out