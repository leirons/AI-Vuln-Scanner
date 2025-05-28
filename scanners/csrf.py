import network_tools as nt
from page_analyzer import PageParser

def check_form_security(target):
    """Перевіряє веб-сторінку на потенційні проблеми з міжсайтовими запитами"""
    try:
        page_data = nt.fetch_page(target)
        page_parser = PageParser(page_data)
        all_forms = page_parser.extract_forms()
        security_issue = False
        
        for web_form in all_forms:
            # Шукаємо захисні токени у формах
            if not web_form.has_security_token() and not web_form.has_protection_field():
                print("[!] Потенційна проблема: форма без захисту від міжсайтових запитів")
                security_issue = True
                
        if not security_issue:
            print("[+] Форми захищені від міжсайтових запитів")
            
        return security_issue
        
    except nt.ConnectionProblem as error:
        print(f"Помилка під час аналізу: {error}")
        return False
