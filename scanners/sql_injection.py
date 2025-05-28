import requests

def scan_sql_injection(url):
    """Проверяет URL на уязвимости внедрения SQL"""
    test_str = "' OR 'a'='a"
    try:
        result = req.retrieve(f"{url}?param={test_str}")
        db_errors = ["SQL syntax", "mysql", "unexpected end"]
        if any(err in result.text for err in db_errors):
            print("[!] Обнаружена возможная SQL-инъекция!")
            return True
        print("[+] SQL-инъекции не обнаружены")
        return False
    except req.ConnectionIssue as e:
        print(f"Ошибка проверки: {e}")
        return False

