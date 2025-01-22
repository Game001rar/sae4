import subprocess
import sys

def installer_paquet(paquet):
    """Installe un paquet en utilisant pip."""
    subprocess.check_call([sys.executable, "-m", "pip", "install", paquet])

def verifier_et_installer(paquet):
    """Vérifie si un paquet est installé, sinon l'installe."""
    try:
        __import__(paquet)
        print(f"Le paquet '{paquet}' est déjà installé.")
    except ImportError:
        print(f"Le paquet '{paquet}' n'est pas installé. Installation en cours...")
        installer_paquet(paquet)

if __name__ == "__main__":
    # Lire les dépendances depuis le fichier requirements.txt
    with open("requirements.txt", "r") as f:
        packages = f.read().splitlines()

    for package in packages:
        verifier_et_installer(package)
