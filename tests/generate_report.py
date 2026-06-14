#!/usr/bin/env python3
"""
TEST-3: Генерация отчёта в tests/report/
Запускает pytest с --cov и сохраняет:
  - tests/report/report.html   (pytest-html, если установлен)
  - tests/report/coverage.xml  (XML покрытие)
  - tests/report/summary.txt   (текстовая сводка)
"""
import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime

# Корень проекта — на уровень выше этого файла
PROJECT_ROOT = Path(__file__).parent.parent
REPORT_DIR = PROJECT_ROOT / "tests" / "report"
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def run_tests():
    """Запускает pytest и собирает отчёт."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Целевые тест-файлы (TEST-1 покрытие)
    test_files = [
        "tests/test_crypto_functions.py",
        "tests/test_vault_storage.py",
        "tests/test_clipboard_operations.py",
        "tests/test_import_export.py",
        "tests/test_additional_coverage.py",
        "tests/test_coverage_boost.py",
        "tests/test_coverage_final.py",
    ]

    # Проверяем наличие pytest-html
    try:
        import pytest_html  # noqa
        has_html = True
    except ImportError:
        has_html = False

    cmd = [
        sys.executable, "-m", "pytest",
        *test_files,
        "-v",
        "--tb=short",
        f"--cov=src",
        "--cov-report=term-missing",
        f"--cov-report=xml:{REPORT_DIR / 'coverage.xml'}",
        f"--cov-report=html:{REPORT_DIR / 'htmlcov'}",
        "--no-header",
        "-q",
    ]

    if has_html:
        cmd += [f"--html={REPORT_DIR / 'report.html'}", "--self-contained-html"]

    print(f"[{now}] Запуск тестов…")
    print(f"Команда: {' '.join(cmd)}\n")

    result = subprocess.run(
        cmd,
        cwd=str(PROJECT_ROOT),
        capture_output=False,
        text=True,
    )
    return result.returncode


def parse_coverage_xml():
    """Читает coverage.xml и возвращает словарь {module: coverage%}."""
    xml_path = REPORT_DIR / "coverage.xml"
    if not xml_path.exists():
        return {}
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_path)
        root = tree.getroot()
        modules = {}
        for pkg in root.iter("package"):
            for cls in pkg.iter("class"):
                name = cls.get("filename", cls.get("name", "?"))
                # Normalise path
                name = name.replace("\\", "/").replace("src/", "")
                line_rate = float(cls.get("line-rate", 0)) * 100
                modules[name] = round(line_rate, 1)
        return modules
    except Exception as e:
        return {"error": str(e)}


def parse_junit_xml():
    """Пытается прочитать junit XML для сводки passed/failed."""
    junit_path = REPORT_DIR / "junit.xml"
    if not junit_path.exists():
        return None
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(junit_path)
        root = tree.getroot()
        # <testsuite tests="…" failures="…" errors="…">
        ts = root if root.tag == "testsuite" else root.find("testsuite")
        if ts is None:
            return None
        total = int(ts.get("tests", 0))
        failures = int(ts.get("failures", 0))
        errors = int(ts.get("errors", 0))
        skipped = int(ts.get("skipped", 0))
        passed = total - failures - errors - skipped
        return {"total": total, "passed": passed, "failed": failures + errors, "skipped": skipped}
    except Exception:
        return None


def write_summary(returncode: int):
    """Пишет текстовую сводку в tests/report/summary.txt."""
    summary_path = REPORT_DIR / "summary.txt"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    modules = parse_coverage_xml()
    junit_stats = parse_junit_xml()

    lines = []
    lines.append("=" * 60)
    lines.append("CryptoSafe — Отчёт тестирования")
    lines.append(f"Дата: {now}")
    lines.append("=" * 60)
    lines.append("")

    # Сводка passed/failed
    lines.append("## Результаты тестов")
    if junit_stats:
        lines.append(f"  Всего:    {junit_stats['total']}")
        lines.append(f"  Прошло:   {junit_stats['passed']}")
        lines.append(f"  Упало:    {junit_stats['failed']}")
        lines.append(f"  Пропуск:  {junit_stats['skipped']}")
    else:
        status = "PASSED" if returncode == 0 else "FAILED"
        lines.append(f"  Статус: {status} (код {returncode})")
    lines.append("")

    # Покрытие по модулям
    lines.append("## Покрытие кода (по модулям)")
    if modules and "error" not in modules:
        for mod, pct in sorted(modules.items(), key=lambda x: -x[1]):
            bar_len = int(pct / 5)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            lines.append(f"  {bar} {pct:5.1f}%  {mod}")
    else:
        lines.append("  (Данные о покрытии недоступны)")
    lines.append("")

    lines.append("## Файлы отчёта")
    lines.append(f"  HTML отчёт:    {REPORT_DIR / 'report.html'}")
    lines.append(f"  HTML покрытие: {REPORT_DIR / 'htmlcov' / 'index.html'}")
    lines.append(f"  XML покрытие:  {REPORT_DIR / 'coverage.xml'}")
    lines.append(f"  JUnit XML:     {REPORT_DIR / 'junit.xml'}")
    lines.append("")
    lines.append("=" * 60)

    text = "\n".join(lines)
    summary_path.write_text(text, encoding="utf-8")
    print("\n" + text)
    print(f"\n[Отчёт сохранён в {summary_path}]")


def main():
    returncode = run_tests()

    # Повторный запуск только с junit для сводки
    junit_path = REPORT_DIR / "junit.xml"
    test_files = [
        "tests/test_crypto_functions.py",
        "tests/test_vault_storage.py",
        "tests/test_clipboard_operations.py",
        "tests/test_import_export.py",
        "tests/test_additional_coverage.py",
    ]
    subprocess.run(
        [
            sys.executable, "-m", "pytest",
            *test_files,
            f"--junitxml={junit_path}",
            "-q", "--no-header", "--tb=no",
        ],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
    )

    write_summary(returncode)
    return returncode


if __name__ == "__main__":
    sys.exit(main())
