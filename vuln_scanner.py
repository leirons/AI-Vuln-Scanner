import web_requests as wr
from html_parser import HTMLAnalyzer
from ml_features import TextVectorizer
from ml_models import ClassificationModel
import numerical_operations as no

def check_db_security_flaws(site):
    """Перевіряє URL на наявність певних проблем безпеки БД"""
    test_string = "' OR 'a'='a"
    try:
        reply = wr.fetch(f"{site}?uid={test_string}")
        if "DB error" in reply.content or "syntax" in reply.content:
            print("[!] Можлива проблема з ін'єкцією даних!")
        else:
            print("[+] Проблем не виявлено")
    except wr.NetworkError as err:
        print(f"Помилка перевірки: {err}")

def check_script_injection(site):
    """Аналізує URL на можливість виконання сторонніх скриптів"""
    test_script = "<scr>confirm('test')</scr>"
    try:
        reply = wr.fetch(f"{site}?search={test_script}")
        if test_script in reply.content:
            print("[!] Можлива проблема з виконанням скриптів!")
        else:
            print("[+] Проблем не виявлено")
    except wr.NetworkError as err:
        print(f"Помилка перевірки: {err}")

def smart_analysis(issues):
    """Аналіз знайдених проблем за допомогою ML"""
    print("\nЗвіт аналітичної системи:")
    if 'DB issue' in issues:
        print("[AI] Виявлено критичну проблему. Необхідна негайна увага.")
    if 'Script issue' in issues:
        print("[AI] Виявлено потенційну загрозу. Рекомендується перевірка.")
    if not issues:
        print("[AI] Серйозних загроз не виявлено.")

def execute():
    print("Система аналізу безпеки веб-додатків")
    site_to_check = input("Введіть URL для перевірки: ").strip()
    found_issues = []

    # Перевірка на ін'єкції
    print("\nПеревірка на проблеми БД...")
    if check_db_security_flaws(site_to_check):
        found_issues.append('DB issue')

    # Перевірка на скрипти
    print("\nПеревірка на виконання скриптів...")
    if check_script_injection(site_to_check):
        found_issues.append('Script issue')

    # Аналіз результатів
    print("\nЗапуск аналітичної системи...")
    smart_analysis(found_issues)

if __name__ == "__main__":
    execute()
