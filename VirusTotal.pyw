import tkinter as tk
from tkinter import filedialog
import requests
import threading
import os

api_key = "5cf17f124471fba99ff48139e6b29620d37f7dea972853c012728d6bb37f838c"

def check_file_virustotal(api_key, file_path):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}

    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        response = requests.post(url, files=files, params=params)

    if response.status_code == 200:
        scan_report = response.json()
        resource = scan_report.get('resource')

        if resource:
            return check_scan_report(api_key, resource)
        else:
            return "Ошибка при проверке файла."
    else:
        return f"Ошибка отправки файла для проверки: {response.status_code}"

def check_scan_report(api_key, resource):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': resource}
    response = requests.get(url, params=params)

    if response.status_code == 200:
        scan_result = response.json()
        positives = scan_result.get('positives', 0)

        if positives > 0:
            scan_results = scan_result.get('scans', {})
            infected_results = [(name, result['result']) for name, result in scan_results.items() if result['detected']]
            infected_results_text = "\n".join([f"{name}: {result}" for name, result in infected_results])
            return f"{positives} антивирусов показали, что этот файл - вирус.\nАнтивирусы:\n{infected_results_text}"
        else:
            return "Вирусов нет."
    else:
        return f"Ошибка получения статистики файла: {response.status_code}"


def browse_file():
    file_path = filedialog.askopenfilename(title="Выбрать файл")
    if file_path:
        threading.Thread(target=scan_file, args=(file_path,)).start()

def scan_file(file_path):
    result_text.config(state=tk.NORMAL)
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, "Проверяем файл...\n")
    result = check_file_virustotal(api_key, file_path)
    result_text.insert(tk.END, result)
    result_text.config(state=tk.DISABLED)

# Создание основного окна
window = tk.Tk()
window.title("VirusChecker")

# Создание кнопки
button = tk.Button(window, text="Выбрать файл", command=browse_file)
button.pack(pady=20)

# Метка для вывода результата
result_text = tk.Text(window, width=50, height=10, state=tk.DISABLED)
result_text.pack()

# Запуск главного цикла окна
window.mainloop()