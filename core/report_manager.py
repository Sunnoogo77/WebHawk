# Gestion globale du scanner
import json
import os
import threading
from datetime import datetime

REPORT_PATH = "reports/webhawk_report.json"
_report_lock = threading.Lock()


def get_report_path(target):
    """Generate a unique report file path for a target."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_name = target.replace("http://", "").replace("https://", "").replace("/", "_")
    report_path = f"reports/{target_name}_{timestamp}.json"
    return report_path


def initialize_report(target):
    """Initialize a new JSON report file for the given target."""
    report_path = get_report_path(target)

    report_data = {
        "target": target,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "results": {}
    }

    if not os.path.exists("reports"):
        os.makedirs("reports")

    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=4)

    return report_path


def update_report(report_path, section, data):
    """Mise à jour du rapport spécifique avec les résultats d'un test (thread-safe)."""
    if not report_path:
        print("⚠️ Aucun chemin de rapport spécifié, section ignorée.")
        return

    if not os.path.exists(report_path):
        print(f"❌ ERREUR : Le rapport {report_path} n'existe pas !")
        return

    with _report_lock:
        try:
            with open(report_path, "r") as f:
                report_data = json.load(f)

            report_data["results"][section] = data

            with open(report_path, "w") as f:
                json.dump(report_data, f, indent=4, default=str)
        except (json.JSONDecodeError, IOError) as e:
            print(f"❌ ERREUR lors de la mise à jour du rapport : {e}")


def finalize_report(report_path):
    """Finalize the report and print its location."""
    if report_path and os.path.exists(report_path):
        # Add scan end time
        with _report_lock:
            try:
                with open(report_path, "r") as f:
                    report_data = json.load(f)
                report_data["scan_end"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(report_path, "w") as f:
                    json.dump(report_data, f, indent=4, default=str)
            except (json.JSONDecodeError, IOError):
                pass
        print(f"\n📄 Rapport final généré : {report_path}\n")
    else:
        print(f"\n❌ Rapport introuvable : {report_path}\n")
    

