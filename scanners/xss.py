import requests

def scan_xss(url):
    """Проверяет URL на XSS уязвимости"""
    js_test = "<scri>alert(1)</scri>"
    try:
        page = req.get(f"{url}?input={js_test}")
        if js_test in page.text:
            print("[!] Обнаружена возможная XSS уязвимость!")
            return True
        print("[+] XSS уязвимостей не обнаружено")
        return False
    except req.HTTPError as e:
        print(f"Ошибка анализа: {e}")
        return False

