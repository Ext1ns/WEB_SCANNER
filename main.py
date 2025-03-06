import requests
from bs4 import BeautifulSoup
import argparse
from urllib.parse import urljoin


# Colors for console results
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'


# Checking SQL-injections
def check_sql_injection(url):
    test_payload = "' OR '1'='1"
    response = requests.get(url + test_payload)
    if "error" in response.text.lower() or "syntax" in response.text.lower():
        print(f"{Colors.RED}[!] Возможна SQL-инъекция на: {url}{Colors.END}")
    else:
        print(f"{Colors.GREEN}[+] SQL-инъекция не обнаружена на: {url}{Colors.END}")


# Checking XSS
def check_xss(url):
    test_payload = "<script>alert('XSS')</script>"
    response = requests.get(url + "?param=" + test_payload)
    if test_payload in response.text:
        print(f"{Colors.RED}[!] Возможна XSS-уязвимость на: {url}{Colors.END}")
    else:
        print(f"{Colors.GREEN}[+] XSS-уязвимость не обнаружена на: {url}{Colors.END}")


# Searching open directories
def find_open_directories(url):
    common_dirs = ["admin", "backup", "config", "logs", "uploads"]
    error_keywords = ["404", "not found", "ошибка", "доступ запрещён"]

    # We get the length of the main page for comparison
    main_page_response = requests.get(url)
    main_page_length = len(main_page_response.text)

    for directory in common_dirs:
        test_url = urljoin(url, directory)
        response = requests.get(test_url, allow_redirects=False)  # Disabling redirects

        # Checking the status code
        if response.status_code == 200:
            content_length = len(response.text)

            # Checking the length of the content
            if content_length == main_page_length:
                print(
                    f"{Colors.GREEN}[+] Директория {test_url} недоступна (длина совпадает с главной страницей).{Colors.END}")
                continue

            # Checking the content for error keywords
            if any(keyword in response.text.lower() for keyword in error_keywords):
                print(f"{Colors.GREEN}[+] Директория {test_url} недоступна (обнаружена страница ошибки).{Colors.END}")
                continue

            # Checking headers
            if "x-error" in response.headers or "x-404" in response.headers:
                print(f"{Colors.GREEN}[+] Директория {test_url} недоступна (обнаружен заголовок ошибки).{Colors.END}")
                continue

            # If all the checks are passed, we consider the directory to be open
            print(f"{Colors.YELLOW}[!] Найдена открытая директория: {test_url}{Colors.END}")

        # Redirect processing
        elif response.status_code in [301, 302, 303, 307, 308]:
            print(f"{Colors.GREEN}[+] Директория {test_url} недоступна (редирект на другую страницу).{Colors.END}")

        # Processing of other status codes
        else:
            print(
                f"{Colors.GREEN}[+] Директория {test_url} недоступна (код состояния: {response.status_code}).{Colors.END}")


# Checking software versions
def check_software_versions(url):
    headers = requests.get(url).headers
    if "server" in headers:
        print(f"{Colors.BLUE}[*] Сервер: {headers['server']}{Colors.END}")
    if "x-powered-by" in headers:
        print(f"{Colors.BLUE}[*] Используемое ПО: {headers['x-powered-by']}{Colors.END}")


# Main scanning function
def scan_website(url):
    print(f"{Colors.BLUE}[*] Начинаем сканирование: {url}{Colors.END}")

    # Checking на SQL-injections
    check_sql_injection(url)

    # Checking XSS
    check_xss(url)

    # Search for open directories
    find_open_directories(url)

    # Checking software versions
    check_software_versions(url)


# Command line argument parsing
def main():
    parser = argparse.ArgumentParser(description="Сканер уязвимостей для веб-сайтов.")
    parser.add_argument("url", help="URL сайта для сканирования.")
    args = parser.parse_args()

    scan_website(args.url)


if __name__ == "__main__":
    main()