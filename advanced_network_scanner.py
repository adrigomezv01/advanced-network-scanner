import customtkinter as ctk
from tkinter import filedialog, messagebox
import subprocess
import threading
import platform
import shutil
import re

# Apariencia
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class NetworkScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Escáner de Red y Puertos")
        self.geometry("980x720")
        self.minsize(900, 650)

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=180, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")

        self.sidebar_label = ctk.CTkLabel(self.sidebar, text="Menú", font=ctk.CTkFont(size=18, weight="bold"))
        self.sidebar_label.pack(pady=(20,10))

        self.btn_scan_tab = ctk.CTkButton(self.sidebar, text="Escaneo", command=self.show_scan_tab)
        self.btn_scan_tab.pack(pady=10, padx=10, fill="x")

        self.btn_help_tab = ctk.CTkButton(self.sidebar, text="Ayuda", command=self.show_help_tab)
        self.btn_help_tab.pack(pady=10, padx=10, fill="x")

        # Contenedor principal
        self.container = ctk.CTkFrame(self, corner_radius=10)
        self.container.pack(side="left", fill="both", expand=True, padx=20, pady=20)

        # Pestañas
        self.tabs = ctk.CTkTabview(self.container)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=10)
        self.tabs.add("Escaneo")
        self.tabs.add("Avanzado")
        self.tabs.add("Resultados")

        # Construir cada pestaña
        self.build_scan_tab()
        self.build_advanced_tab()
        self.build_results_tab()

        # Estado inicial
        self.tabs.set("Escaneo")

    def show_scan_tab(self):
        self.tabs.set("Escaneo")

    def show_help_tab(self):
        messagebox.showinfo("Ayuda", 
            "Esta aplicación permite escanear redes y puertos usando Nmap.\n\n"
            "1. Introduce la IP o rango.\n"
            "2. Elige opciones y pulsa 'Iniciar escaneo'.\n"
            "3. Revisa y guarda los resultados en la pestaña correspondiente.\n\n"
            "Desarrollado con CustomTkinter y Nmap."
        )

    def build_scan_tab(self):
        tab = self.tabs.tab("Escaneo")

        label = ctk.CTkLabel(tab, text="Escaneo Rápido", font=ctk.CTkFont(size=20, weight="bold"))
        label.pack(pady=15)

        frame_inputs = ctk.CTkFrame(tab)
        frame_inputs.pack(pady=10, padx=20, fill="x")

        ctk.CTkLabel(frame_inputs, text="Objetivo (IP, host o rango):", width=180, anchor="e").grid(row=0, column=0, padx=5, pady=10)
        self.entry_target_simple = ctk.CTkEntry(frame_inputs, width=300, placeholder_text="Ej: 192.168.1.136 o scanme.nmap.org")
        self.entry_target_simple.grid(row=0, column=1, padx=5, pady=10)

        btn_scan = ctk.CTkButton(tab, text="Iniciar escaneo rápido", command=self.run_simple_scan, width=200)
        btn_scan.pack(pady=15)

    def build_advanced_tab(self):
        tab = self.tabs.tab("Avanzado")

        label = ctk.CTkLabel(tab, text="Escaneo Avanzado", font=ctk.CTkFont(size=20, weight="bold"))
        label.pack(pady=15)

        frame_inputs = ctk.CTkFrame(tab)
        frame_inputs.pack(pady=10, padx=20, fill="x")

        ctk.CTkLabel(frame_inputs, text="Objetivo (IP, host o rango):", width=180, anchor="e").grid(row=0, column=0, padx=5, pady=8)
        self.entry_target_adv = ctk.CTkEntry(frame_inputs, width=300, placeholder_text="Ej: 192.168.1.136 o scanme.nmap.org")
        self.entry_target_adv.grid(row=0, column=1, padx=5, pady=8)

        ctk.CTkLabel(frame_inputs, text="Puertos (ej: 80,443 o 1-1000):", width=180, anchor="e").grid(row=1, column=0, padx=5, pady=8)
        self.entry_ports_adv = ctk.CTkEntry(frame_inputs, width=150, placeholder_text="Opcional")
        self.entry_ports_adv.grid(row=1, column=1, padx=5, pady=8, sticky="w")

        ctk.CTkLabel(frame_inputs, text="Tipo de escaneo:", width=180, anchor="e").grid(row=2, column=0, padx=5, pady=8)
        self.scan_type_var = ctk.StringVar(value="Rápido")
        combo_scan = ctk.CTkComboBox(frame_inputs, variable=self.scan_type_var, values=["Rápido", "Completo"], width=150)
        combo_scan.grid(row=2, column=1, padx=5, pady=8, sticky="w")

        self.service_var = ctk.BooleanVar(value=False)
        chk_service = ctk.CTkCheckBox(frame_inputs, text="Detección de servicios (-sV)", variable=self.service_var)
        chk_service.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        self.os_var = ctk.BooleanVar(value=False)
        chk_os = ctk.CTkCheckBox(frame_inputs, text="Detección de sistema operativo (-O)", variable=self.os_var)
        chk_os.grid(row=4, column=1, padx=5, pady=5, sticky="w")

        frame_buttons = ctk.CTkFrame(tab)
        frame_buttons.pack(pady=15)

        btn_scan = ctk.CTkButton(frame_buttons, text="Iniciar escaneo avanzado", command=self.run_advanced_scan, width=220)
        btn_scan.pack(side="left", padx=10)

        btn_clear = ctk.CTkButton(frame_buttons, text="Limpiar resultados", command=self.clear_results, width=160)
        btn_clear.pack(side="left", padx=10)

        btn_save = ctk.CTkButton(frame_buttons, text="Guardar resultados", command=self.save_results, width=160)
        btn_save.pack(side="left", padx=10)

    def build_results_tab(self):
        tab = self.tabs.tab("Resultados")
        label = ctk.CTkLabel(tab, text="Resultados del escaneo", font=ctk.CTkFont(size=20, weight="bold"))
        label.pack(pady=15)

        self.textbox_results = ctk.CTkTextbox(tab, width=900, height=470, font=("Consolas", 12), wrap="word")
        self.textbox_results.pack(padx=15, pady=10)

        self.progress_bar = ctk.CTkProgressBar(tab, width=900)
        self.progress_bar.pack(pady=10)
        self.progress_bar.set(0)

    def run_simple_scan(self):
        target = self.entry_target_simple.get().strip()
        if not target:
            messagebox.showwarning("Campo vacío", "Por favor, introduce una IP, dominio o rango.")
            return
        self.clear_results()
        cmd = [self.get_nmap_command()]
        cmd += ["-F", target]
        self.execute_scan(cmd)

    def run_advanced_scan(self):
        target = self.entry_target_adv.get().strip()
        ports = self.entry_ports_adv.get().strip()
        scan_type = self.scan_type_var.get()
        detect_service = self.service_var.get()
        detect_os = self.os_var.get()

        if not target:
            messagebox.showwarning("Campo vacío", "Por favor, introduce una IP, dominio o rango.")
            return

        # Validación de puertos
        if ports and not re.match(r'^(\d+(-\d+)?)(,(\d+(-\d+)?))*$', ports):
            messagebox.showerror("Error", "Formato de puertos inválido. Ejemplo válido: 80,443,1000-2000")
            return

        cmd = [self.get_nmap_command()]
        if ports:
            cmd += ["-p", ports]
        else:
            if scan_type == "Rápido":
                cmd += ["-F"]
            elif scan_type == "Completo":
                cmd += ["-p-", "-T4"]
        if detect_service:
            cmd.append("-sV")
        if detect_os:
            cmd.append("-O")
        cmd.append(target)

        self.clear_results()
        self.execute_scan(cmd)

    def execute_scan(self, cmd):
        self.tabs.set("Resultados")
        self.textbox_results.configure(state="normal")
        self.textbox_results.delete("0.0", "end")
        self.textbox_results.insert("end", f"Ejecutando: {' '.join(cmd)}\n\n")
        self.textbox_results.configure(state="disabled")
        self.progress_bar.start()

        def scan_thread():
            try:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                out, err = process.communicate()
                self.progress_bar.stop()
                self.textbox_results.configure(state="normal")
                if out:
                    self.insert_results_with_emojis(out)
                if err:
                    self.textbox_results.insert("end", err)
                self.textbox_results.configure(state="disabled")
            except FileNotFoundError:
                self.progress_bar.stop()
                self.textbox_results.configure(state="normal")
                self.textbox_results.insert("end", "Error: Nmap no está instalado o no se encuentra en el PATH.\n"
                                                   "Por favor, instala Nmap y reinicia tu terminal.")
                self.textbox_results.configure(state="disabled")
            except Exception as e:
                self.progress_bar.stop()
                self.textbox_results.configure(state="normal")
                self.textbox_results.insert("end", f"Error: {e}")
                self.textbox_results.configure(state="disabled")

        threading.Thread(target=scan_thread, daemon=True).start()

    def insert_results_with_emojis(self, text):
        # Inserta texto y añade emojis para puertos abiertos/cerrados
        self.textbox_results.delete("0.0", "end")
        lines = text.splitlines()
        for line in lines:
            if re.search(r'\bopen\b', line):
                self.textbox_results.insert("end", f"🟢 {line}\n")
            elif re.search(r'\bclosed\b', line):
                self.textbox_results.insert("end", f"🔴 {line}\n")
            elif re.search(r'\bfiltered\b', line):
                self.textbox_results.insert("end", f"🟡 {line}\n")
            else:
                self.textbox_results.insert("end", line + "\n")

    def clear_results(self):
        self.textbox_results.configure(state="normal")
        self.textbox_results.delete("0.0", "end")
        self.textbox_results.configure(state="disabled")

    def save_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.textbox_results.get("0.0", "end"))
            messagebox.showinfo("Guardado", f"Resultados guardados en {file_path}")

    def get_nmap_command(self):
        if platform.system() == "Windows":
            nmap_path = shutil.which("nmap.exe")
            if nmap_path:
                return nmap_path
            else:
                return "nmap.exe"
        else:
            return "nmap"

if __name__ == "__main__":
    app = NetworkScannerApp()
    app.mainloop()
