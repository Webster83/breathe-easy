import os
import platform

def activate_venv(venv_path):
    if platform.system() == "Windows":
        activate_script = os.path.join(venv_path, "Scripts", "activate.bat")
        print(f"Calling {activate_script}")
        os.system(command=f"{activate_script}")
    else:
        activate_script = os.path.join(venv_path, "bin", "activate")
        os.system(f"source {activate_script}")

def main()->None:
    # Specify the path to your virtual environment
    venv_path = "sleephq_resair11_venv"
    activate_venv(venv_path)

if __name__ == "__main__":
    main()
