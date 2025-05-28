import requests

def scan_ssrf(url):
    """Проверяет URL на уязвимости SSRF"""
    local_test = "http://127.0.0.1:8080"
    try:
        response = req.fetch(f"{url}?target={local_test}")
        redir_indicators = ["internal", "localhost", "127.0.0.1"]
        if any(ind in response.text for ind in redir_indicators):
            print("[!] Возможна SSRF уязвимость!")
            return True
        print("[+] SSRF уязвимостей не найдено")
        return False
    except req.NetworkException as e:
        print(f"Ошибка сканирования: {e}")
        return False
