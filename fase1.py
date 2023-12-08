import threading
import tkinter as tk
from tkinter import ttk
from scapy.all import ARP, Ether, srp
import socket
import threading
import asyncio
import nmap
def escanear_rango_con_hilos(rango):
    resultados = []
    hilos = []

    for ip in rango:
        hilo = threading.Thread(target=lambda: resultados.extend(escanear_rango(ip)), daemon=True)
        hilos.append(hilo)

    for hilo in hilos:
        hilo.start()

    for hilo in hilos:
        hilo.join()
    return resultados
def escanear_rango_nmap(rango):
    nm = nmap.PortScanner()
    nm.scan(hosts=rango, arguments='-sn')
    dispositivos = [{'ip': host, 'hostname': nm[host].hostname()} for host in nm.all_hosts()]
    return dispositivos

async def escanear_red(ip):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    respuesta = srp(arp_request, timeout=3, verbose=0)[0]

    dispositivos = []
    for index, (sent, received) in enumerate(respuesta, 1):
        ip = received.psrc
        mac = received.hwsrc
        try:
            nombre_de_pc = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            nombre_de_pc = "No disponible"

        dispositivos.append({'indice': index, 'ip': ip, 'mac': mac, 'nombre_de_pc': nombre_de_pc})

    carga_var.set(100)  # Establecer el valor de carga al 100%
    resultados_text.delete(1.0, tk.END)  # Limpiar el texto anterior

    resultados_text.insert(tk.END, "Dispositivos en la red:\n")
    for dispositivo in dispositivos:
        resultados_text.insert(tk.END, f"{dispositivo['indice']}. IP: {dispositivo['ip']}, MAC: {dispositivo['mac']}, Nombre de PC: {dispositivo['nombre_de_pc']}\n")
def comenzar_escaneo():
    red_ip = entrada_ip.get()  # Obtener la IP ingresada por el usuario

    # Mostrar la barra de progreso en la misma ventana
    barra_progreso.pack(pady=10)

    # Iniciar el escaneo en un hilo para no bloquear la interfaz gráfica
    hilo_escaneo = threading.Thread(target=escanear_red, args=(red_ip,))
    hilo_escaneo.start()

    # Actualizar la barra de progreso mientras el hilo de escaneo está en ejecución
    ventana.after(100, verificar_progreso)

def verificar_progreso():
    valor_carga = carga_var.get()
    if valor_carga < 100:
        # Si el escaneo no ha terminado, actualizar la barra de progreso después de 100 ms
        barra_progreso['value'] = valor_carga
        ventana.after(100, verificar_progreso)
    else:
        # Si el escaneo ha terminado, ocultar la barra de progreso
        barra_progreso.pack_forget()

# Crear la interfaz gráfica
ventana = tk.Tk()
ventana.title("Escáner de Red")

# Cuadro de entrada para la IP
etiqueta_ip = tk.Label(ventana, text="Ingrese la IP:")
etiqueta_ip.pack(pady=5)

entrada_ip = tk.Entry(ventana)
entrada_ip.pack(pady=5)

# Barra de progreso
carga_var = tk.DoubleVar()
barra_progreso = ttk.Progressbar(ventana, variable=carga_var, length=200, mode='determinate')

# Botón para comenzar el escaneo
boton_comenzar = tk.Button(ventana, text="Comenzar Escaneo", command=comenzar_escaneo)
boton_comenzar.pack(pady=10)

# Área de texto expandible para mostrar los resultados
resultados_text = tk.Text(ventana, height=10, width=60, wrap=tk.WORD)
resultados_text.pack(expand=True, fill=tk.BOTH, pady=10, padx=10)

# Iniciar el bucle de la interfaz gráfica
ventana.mainloop()
