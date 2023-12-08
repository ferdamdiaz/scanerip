import tkinter as tk
from tkinter import ttk
import concurrent.futures
import socket
import platform
from scapy.all import Ether, ARP, srp

class FormularioBusqueda:
    def __init__(self, root):
        self.root = root
        self.root.title("Búsqueda de Dispositivos en la Red")

        self.label_rango_ip = ttk.Label(root, text="Rango de IP:")
        self.label_rango_ip.grid(row=0, column=0, padx=10, pady=10, sticky=tk.E)

        self.entry_rango_ip = ttk.Entry(root)
        self.entry_rango_ip.grid(row=0, column=1, padx=10, pady=10)

        self.boton_buscar = ttk.Button(root, text="Buscar", command=self.realizar_busqueda)
        self.boton_buscar.grid(row=1, column=0, columnspan=2, pady=10)

        self.resultado_texto = tk.Text(root, height=30, width=100)
        self.resultado_texto.grid(row=2, column=0, columnspan=2, pady=10)

    def realizar_busqueda(self):
        rango_ip = self.entry_rango_ip.get()
        dispositivos_en_red = self.escanear_red(rango_ip)

        resultado = "Dispositivos encontrados:\n"
        for dispositivo in dispositivos_en_red:
            resultado += f"IP: {dispositivo['ip']}, Nombre: {dispositivo['nombre']}, MAC: {dispositivo['mac']}\n"

        self.resultado_texto.delete(1.0, tk.END)
        self.resultado_texto.insert(tk.END, resultado)

    def escanear_red(self, ip):
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        respuesta = srp(arp_request, timeout=3, verbose=0)[0]

        dispositivos = []
        for sent, received in respuesta:
            ip = received.psrc
            mac = received.hwsrc
            try:
                nombre = socket.gethostbyaddr(ip)[0]
            except socket.error:
                nombre = "No disponible"

            dispositivos.append({'ip': ip, 'nombre': nombre, 'mac': mac})

        return dispositivos

if __name__ == "__main__":
    root = tk.Tk()
    app = FormularioBusqueda(root)
    root.mainloop()
