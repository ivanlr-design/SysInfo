import platform,os,sys,socket,time,win32net
import webbrowser,signal,pyaudio,winreg
from typing import Any
import requests,ctypes,psutil
import subprocess,re,win32netcon,win32net
from subprocess import PIPE
import win32evtlog,re
import win32evtlogutil,browser_cookie3
import threading
import mysql.connector
from scapy.all import *
from colorama import init, Fore, Back, Style
init(autoreset=True)

PortScannerConfig = {
    "Initial_Port":1, #Puerto al que empezara a buscar
    "Ports_To_Scan":10000 #Puerto al que acaba de buscar
}

IpRange = "192.168.100.0/24"
banner = Fore.RED + ''' 
   _____ _               _                 _____        __       
  / ____| |             | |               |_   _|      / _|      
 | (___ | |__   __ _  __| | _____      __   | |  _ __ | |_ ___   
  \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /   | | | '_ \|  _/ _ \  
  ____) | | | | (_| | (_| | (_) \ V  V /   _| |_| | | | || (_) | 
 |_____/|_| |_|\__,_|\__,_|\___/ \_/\_/   |_____|_| |_|_| \___/  
                                                                 
'''

class PcInfo():
    def __init__(self,action) -> None:
        if bool(action) == True:
            
            self.banner = Fore.RED + ''' 
     _____ _               _                 _____        __       
    / ____| |             | |               |_   _|      / _|      
   | (___ | |__   __ _  __| | _____      __   | |  _ __ | |_ ___   
    \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /   | | | '_ \|  _/ _ \  
    ____) | | | | (_| | (_| | (_) \ V  V /   _| |_| | | | || (_) | 
   |_____/|_| |_|\__,_|\__,_|\___/ \_/\_/   |_____|_| |_|_| \___/  
                                                                    
                                                                    
    ''' + Style.RESET_ALL
            self.Mac = False
            self.IP = False
            self.InfoIp = False
            self.IdentifyNumber = False
            self.HWID = False
            os.system("cls")
            time.sleep(0.2)
            print(self.banner)
            time.sleep(0.8)
            os.system("cls")
            self.Main()
            pass
        else:
            pass
    
    def obtener_servicio(self,puerto):
        try:
            nombre_servicio = socket.getservbyport(puerto)
            return nombre_servicio
        except OSError:
            return "Desconocido"

    def Port_Scan(self):
        def escanear_puertos(direccion_ip, puerto_inicial, puerto_final, resultados):
            for puerto in range(puerto_inicial, puerto_final + 1):
                paquete = IP(dst=direccion_ip)/TCP(dport=puerto, flags="S")
                respuesta = sr1(paquete, timeout=0.5, verbose=0)
                if respuesta and respuesta.haslayer(TCP) and respuesta[TCP].flags == 0x12:
                    resultados.append(puerto)

        direccion = "127.0.0.1"

        puerto_inicial = PortScannerConfig.get("Initial_Port")
        puerto_final = PortScannerConfig.get("Ports_To_Scan")

        puertos_abiertos = []

        num_hilos = 10

        puertos_por_hilo = (puerto_final - puerto_inicial + 1) // num_hilos

        hilos = []
        for _ in range(num_hilos):
            hilo = threading.Thread(target=escanear_puertos, args=(direccion, puerto_inicial, puerto_inicial + puertos_por_hilo - 1, puertos_abiertos))
            hilos.append(hilo)
            puerto_inicial += puertos_por_hilo

        for hilo in hilos:
            hilo.start()

        for hilo in hilos:
            hilo.join()

        return puertos_abiertos


    def get_History(self):
        URLS = {}
        from browser_history import get_history

        outputs = get_history()

        his = outputs.histories

        for i in his:
            URL = i[1]
            if URL not in URLS:
                URLS[URL] = 1
            else:
                URLS[URL] += 1
        return URLS

    def get_cookies(self):
        cookies = list(browser_cookie3.chrome())
        return cookies

    def monitorear_eventos(self):
        correos = []
        log_handle = win32evtlog.OpenEventLog(None, "Security")
        
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        pos = 0
        
        try:
            while True:
                events = win32evtlog.ReadEventLog(log_handle, flags, pos)
                if not events:
                    break
                
                for event in events:
                    event_data = win32evtlogutil.SafeFormatMessage(event, log_handle)
                    patron = r"user=([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4})"

                    coincidencias = re.search(patron, event_data)

                    if coincidencias:
                        correo_electronico = coincidencias.group(1)
                        if correo_electronico not in correos:
                            correos.append(correo_electronico)
                
                pos = events[-1].RecordNumber  # Actualiza la posición
                
        except KeyboardInterrupt:
            pass
        
        win32evtlog.CloseEventLog(log_handle)
        return correos

    def get_Users(self):

        names=[]; resumeHandle=0
        while True:
            data,_,resumeHandle=win32net.NetUserEnum(None,0,
                    win32netcon.FILTER_NORMAL_ACCOUNT,resumeHandle)
            names.extend(e["name"] for e in data)
            if not resumeHandle: break
        del data,resumeHandle
        return names

    def Ip_Info(self,ip):
        url = f"https://ipinfo.io/{ip}/json"
        respuesta = requests.get(url)
        
        if respuesta.status_code == 200:
            datos = respuesta.json()
            return datos
        else:
            return None

    def getIdentifyNumber(self):
        text = ""
        command = subprocess.Popen("wmic path win32_computersystemproduct get identifyingnumber",shell=True,stdout=PIPE,stderr=PIPE,stdin=PIPE)
        command.wait()
        s = command.communicate()
        for i in s:
            text += i.decode()
        
        text = text.split("\n")
        identifynumber = text[1]
        return identifynumber

    def getUUID(self):
        text = ""
        command = subprocess.Popen("wmic csproduct get UUID",shell=True,stdout=PIPE,stderr=PIPE,stdin=PIPE)
        command.wait()
        s  =command.communicate()

        for i in s:
            text += i.decode()

        text = text.split("\n")
        UUID = text[1]
        return UUID
    
    def ipv4(self):
        # Obtener la dirección IPV4 pública utilizando el servicio ipify
        response = requests.get("https://api.ipify.org")

        # Si la respuesta es correcta, imprimir la dirección IPV4 pública 
        if response.status_code == 200:
            public_ip = response.text
        else:
            public_ip = ""

        return public_ip

    def local_ip(self):
        host_name = socket.gethostname()
        ip_local = socket.gethostbyname(host_name)
        return ip_local
    
    def ipv6(self): 
        host_name = socket.gethostname()
        try:
            ip_local = socket.getaddrinfo(host_name, None, socket.AF_INET6)[0][4][0]
            return ip_local
        except socket.gaierror:
            return "IPv6 no disponible en esta máquina"

    
    def IsUserActive(self,User):
        command = subprocess.Popen(f"net user {User}",shell=True,stdout=PIPE,stderr=PIPE,stdin=PIPE)
        command.wait()
        comm  =command.communicate()
        comm = str(comm)

        comm = comm.replace("\\n","\n")
        comm = comm.replace("\\r","\r")
        comm = comm.replace("\\xa2","o")
        comm = comm.replace("\\xa1","i")
        comm = comm.replace("b'","")
        comm = comm.replace("b''","")
        comm = comm.replace("(","")
        comm = comm.replace(")","")
        comm = comm.replace("',","")
        comm = comm.replace("'","")
        # Define la expresión regular
        patron = r"Cuenta activa\s+(Si|No)"

        # Busca la coincidencia en la línea
        coincidencias = re.search(patron, comm)

        if coincidencias:
            estado_cuenta = coincidencias.group(1)
            return estado_cuenta
        else:
            patron = r"Account Active\s+(Yes|No)"

            # Busca la coincidencia en la línea
            coincidencias = re.search(patron, comm)

            if coincidencias:
                estado_cuenta = coincidencias.group(1)
                return estado_cuenta
            else:
                return "UNABLE TO GET STATUS"
    
    def SearchForVulnerabilitis(self,User):
        command = subprocess.Popen(f"net user {User}",shell=True,stdout=PIPE,stderr=PIPE,stdin=PIPE)
        command.wait()
        comm  =command.communicate()
        comm = str(comm)

        comm = comm.replace("\\n","\n")
        comm = comm.replace("\\r","\r")
        comm = comm.replace("\\xa2","o")
        comm = comm.replace("\\xa1","i")
        comm = comm.replace("\\xa4","ñ")
        comm = comm.replace("b'","")
        comm = comm.replace("b''","")
        comm = comm.replace("(","")
        comm = comm.replace(")","")
        comm = comm.replace("',","")
        comm = comm.replace("'","")
        # Define la expresión regular
        patron = r"Contraseña requerida\s+(No|Si)"
        # Busca la coincidencia en la línea
        coincidencias = re.search(patron, comm)

        if coincidencias:
            estado_cuenta = coincidencias.group(1)
            if estado_cuenta == "No":
                patron = r"Miembros del grupo local\s+\*(\w+)"
                coincidencias = re.search(patron, comm)
                if coincidencias:
                    if "Admin" in coincidencias.group(1):
                        print(f"{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.RED}{User}{Fore.YELLOW} dont have password and pertain a Administrator group!{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.RED}{User}{Fore.YELLOW} dont have password and pertain a {coincidencias.group(1)} group!{Style.RESET_ALL}")

        else:
                # Define la expresión regular
            patron = r"Password required\s+(No|Yes)"
            # Busca la coincidencia en la línea
            coincidencias = re.search(patron, comm)

            if coincidencias:
                estado_cuenta = coincidencias.group(1)
                if estado_cuenta == "No":
                    patron = r"Local group members\s+\*(\w+)"
                    coincidencias = re.search(patron, comm)
                    if coincidencias:
                        if "Admin" in coincidencias.group(1):
                            print(f"{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.RED}{User}{Fore.YELLOW} dont have password and pertain a Administrator group!{Style.RESET_ALL}")
                        else:
                            print(f"{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.RED}{User}{Fore.YELLOW} dont have password and pertain a {coincidencias.group(1)} group!{Style.RESET_ALL}")
            else:
                return "UNABLE TO GET STATUS"


    def getmac(self):
        command = subprocess.Popen("getmac",shell=True,stdout=PIPE,stderr=PIPE,stdin=PIPE)

        command.wait()

        comm = command.communicate()

        comm = str(comm)

        comm = comm.replace("\\n","\n")
        comm = comm.replace("\\r","\r")
        comm = comm.replace("\\xa2","o")
        comm = comm.replace("\\xa1","i")
        comm = comm.replace("b'","")
        comm = comm.replace("b''","")
        comm = comm.replace("(","")
        comm = comm.replace(")","")
        comm = comm.replace("',","")
        comm = comm.replace("'","")
        
        # Expresión regular para capturar direcciones MAC
        regex = r'([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})'

        # Buscar todas las coincidencias en el texto
        matches = re.findall(regex, comm)

        return matches

    def mic_en_uso(self):
        try:
            p = pyaudio.PyAudio()
            for i in range(p.get_device_count()):
                dev_info = p.get_device_info_by_index(i)
                if dev_info['maxInputChannels'] > 0:
                    name = dev_info['name']
                    if p.is_format_supported(rate=44100, input_device=i, input_channels=1, input_format=pyaudio.paInt16):
                        
                        return name,True
        except Exception as e:
            return "Error",False
        
        return False,False

    def GetHWID(self):
        UUID = self.getUUID()
        IdentifyNumber = self.getIdentifyNumber()

        return UUID, IdentifyNumber

    def Check_For_Mysql(self):
        founded = False
        processes = []
        config = {
        'user': 'root',
        'password': '',
        'host': 'localhost', 
        }
        for i in psutil.process_iter():

            if i.name() == "mysqld.exe":
                founded = True
                if i.name() not in processes:
                    processes.append(i.name())
                    try:
                        connection = mysql.connector.connect(**config)
                        
                        if connection.is_connected():
                            version = connection.get_server_info()
                            return version
                    except mysql.connector.Error as e:
                        return "ConexionError"
                
        if founded == False:
            return False

    def Main(self):
        if __name__ == "__main__":
            UUID, IdentifyNumber = self.GetHWID()
            print(f"{Fore.YELLOW}*****************{Fore.RED}NETWORKING{Fore.YELLOW}*****************{Style.RESET_ALL}")
            time.sleep(0.5)
            IPV4 = self.ipv4()
            data = self.Ip_Info(IPV4)
            print(f"\n{Fore.GREEN}IPV4{Style.RESET_ALL}: {Fore.BLUE}{IPV4}{Style.RESET_ALL}")
            time.sleep(0.2)
            print(f"\n   |   {Fore.YELLOW}IP INFO{Style.RESET_ALL}  ")
            time.sleep(0.2)
            
            if data:
                print(f"   ---- {Fore.GREEN}Hostname{Style.RESET_ALL} : {Fore.MAGENTA}{data.get('hostname', 'N/A')}{Style.RESET_ALL}")
                time.sleep(0.2)
                print(f"   |   ")
                time.sleep(0.2)
                print(f"   ---- {Fore.GREEN}Ubicación{Style.RESET_ALL}: {Fore.YELLOW}{data.get('city', 'N/A')}{Style.RESET_ALL}, {Fore.BLUE}{data.get('region', 'N/A')}{Style.RESET_ALL}, {Fore.CYAN}{data.get('country', 'N/A')}{Style.RESET_ALL}")
                time.sleep(0.2)
                print(f"   |   ")
                time.sleep(0.2)
                print(f"   ---- {Fore.GREEN}Proveedor de servicios de Internet ({Fore.YELLOW}ISP{Fore.GREEN}){Style.RESET_ALL}: {Fore.CYAN}{data.get('org', 'N/A')}{Style.RESET_ALL}\n")
                time.sleep(0.2)
                print(f"   |   ")
                time.sleep(0.2)
                print(f"   ---- {Fore.GREEN}Postal: {Style.RESET_ALL}: {Fore.CYAN}{data.get('postal', 'N/A')}{Style.RESET_ALL}\n")
                time.sleep(0.2)
                print(f"   |   ")
                time.sleep(0.2)
                print(f"   ---- {Fore.GREEN}Loc: {Style.RESET_ALL}: {Fore.CYAN}{data.get('loc', 'N/A')}{Style.RESET_ALL}\n")
            else:
                print(f"   ---- {Fore.RED}UNABLE TO GET INFORMATION!\n{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Local Ipv4{Style.RESET_ALL}: {self.local_ip()}")
            time.sleep(0.2)
            print(f"{Fore.GREEN}IPV6{Style.RESET_ALL}: {self.ipv6()}")
            time.sleep(0.2)
            print(f"\n{Fore.YELLOW}*****************{Fore.RED}MACS{Fore.YELLOW}*****************{Style.RESET_ALL}\n")
            macs = self.getmac()
            for i in macs:
                i  = str(i)
                i = i.replace("-",":")
                print(f"{Fore.GREEN}MAC{Style.RESET_ALL}: {i}")
                time.sleep(0.2)
            print(f"\n{Fore.YELLOW}*****************{Fore.RED}EXTRACTED INFO{Fore.YELLOW}*****************{Style.RESET_ALL}\n")
            correos = self.monitorear_eventos()
            if correos:
                time.sleep(0.2)
                print(f"{Fore.GREEN}Emails Finded{Style.RESET_ALL}: {Fore.RED}{len(correos)}\n{Style.RESET_ALL}")
                time.sleep(0.2)
                for i in correos:
                    print(f"{Fore.GREEN}Email{Style.RESET_ALL}: {Fore.RED}{i}{Style.RESET_ALL}\n")
                    time.sleep(0.2)
            else:
                print(f"{Fore.GREEN}Emails Finded{Style.RESET_ALL}: {Fore.GREEN}0\n{Style.RESET_ALL}")

            Users = self.get_Users()

            if Users:
                time.sleep(0.2)
                print(f"{Fore.GREEN}Users Finded{Style.RESET_ALL}: {Fore.CYAN}{len(Users)}\n{Style.RESET_ALL}")
                time.sleep(0.2)
                for i in Users:
                    s = self.IsUserActive(i)
                    print(f"{Fore.GREEN}User{Style.RESET_ALL}: {Fore.CYAN}{i}   Active = {s}{Style.RESET_ALL}")
                    time.sleep(0.2)
            else:
                time.sleep(0.2)
                print(f"{Fore.RED}Unable to get Users!{Style.RESET_ALL}\n")
                time.sleep(0.2)
            time.sleep(0.5)
            print(f"\n{Fore.YELLOW}*************************{Fore.GREEN}HISTORY{Fore.YELLOW}*************************{Style.RESET_ALL}")
            time.sleep(0.5)
            URLS = self.get_History()
            if URLS:
                times = 0
                show = True
                print(f"{Fore.GREEN}Total URLS{Style.RESET_ALL}: {Fore.CYAN}{len(URLS)}\n{Style.RESET_ALL}")
                if os.path.exists("History.txt"):
                    os.remove("History.txt")
                for i in URLS:
                    if show == True:
                        print(f"{Fore.GREEN}URL{Style.RESET_ALL}: {Fore.CYAN}{i}\t{Fore.BLUE}Time visited: {Fore.RED}{URLS.get(i)}{Style.RESET_ALL}")
                        time.sleep(0.01)
                    times += 1
                    if times > 100:
                        if show == True:
                            time.sleep(1)
                            print(f"{Fore.RED}There is more than 100 URLS To show so we saved to History.txt!{Style.RESET_ALL}\n")
                        
                        with open("History.txt","a") as file:
                            file.write(f"URL: {i}\tTime visited: {URLS.get(i)}\n")
                            file.close()
                        if show == True:
                            time.sleep(1)
                            show = False
            else:
                print(f"\n{Fore.RED}Unable to get history!{Style.RESET_ALL}\n")
            time.sleep(0.5)
            print(f"\n{Fore.YELLOW}*************************{Fore.GREEN}COOKIES{Fore.YELLOW}*************************{Style.RESET_ALL}")
            time.sleep(0.5)
            cookies = self.get_cookies()

            if cookies:
                time.sleep(0.6)
                print(f"\n{Fore.GREEN}Total Cookies{Style.RESET_ALL}: {Fore.CYAN}{len(cookies)}\n{Style.RESET_ALL}")
                if os.path.exists("Cookies.txt"):
                    os.remove("Cookies.txt")
                for i in cookies:
                    
                    with open("Cookies.txt","a") as file:
                        file.write(f"{i}\n")
                time.sleep(2)
                print(f"{Fore.GREEN}All cookies are saved to Cookies.txt!{Style.RESET_ALL}")
            time.sleep(0.5)
            print(f"\n{Fore.YELLOW}*************************{Fore.GREEN}USERS VULNERABILITIS{Fore.YELLOW}*************************{Style.RESET_ALL}")
            time.sleep(0.5) 
            for i in Users:
                self.SearchForVulnerabilitis(i)
                time.sleep(0.2)
            
            name,uso = self.mic_en_uso()
            if name == "Error":
                print(f"{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.RED} An Error has ocurred!{Style.RESET_ALL}")
                time.sleep(1)
            elif name == "False":
                print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {Fore.BLUE} Microphone is not in use{Style.RESET_ALL}")
                time.sleep(1)
            else:
                print(f"\n{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.RED} Microphone Is in Use!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.RED} Aplication : {Fore.YELLOW}{name}{Style.RESET_ALL}")
                time.sleep(1)

            time.sleep(0.5)
            print(f"\n{Fore.BLUE}Trying to connect to mysql database...{Style.RESET_ALL}\n")
            time.sleep(1)
            version = self.Check_For_Mysql()
            if version == False:
                time.sleep(1)
                print(f"{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.BLUE}Unable to find to mysql!{Style.RESET_ALL}")
                time.sleep(0.5)
                print(f"\n{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.BLUE}trying to connect to find Pls initialize the service!{Style.RESET_ALL}")
                time.sleep(0.5)
                print(f"{Fore.RED}CTRL + C To stop Searching for mysql database{Style.RESET_ALL}")
                while True:
                    try:
                        s = self.Check_For_Mysql()
                        if s == False:
                            print(f"{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.BLUE}Unable to find to mysql!{Style.RESET_ALL}")
                            time.sleep(0.5)
                        elif s == "ConexionError":
                            print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {Fore.BLUE}Mysql Finded!{Style.RESET_ALL}")
                            time.sleep(2)
                            print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {Fore.BLUE}Trying to connect...!{Style.RESET_ALL}")
                            time.sleep(1)
                            print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {Fore.GREEN}Conexion Refused! No vulnerable{Style.RESET_ALL}")
                            time.sleep(3)
                            break
                        else:
                            print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {Fore.BLUE}Mysql Finded!{Style.RESET_ALL}")
                            time.sleep(2)
                            print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {Fore.BLUE}Trying to connect...!{Style.RESET_ALL}")
                            time.sleep(1)
                            print(f"{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.YELLOW}Mysql Root has no password! Vulnerable{Style.RESET_ALL}")
                            print(f"{Fore.GREEN}Mysql Version: {Fore.RED}{version}{Style.RESET_ALL}")
                            time.sleep(3)
                            break

                    except KeyboardInterrupt:
                        print(f"\n{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.BLUE}Stop Searching...{Style.RESET_ALL}")
                        time.sleep(2)
                        break
                time.sleep(0.8)
            elif s == "ConexionError":
                print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {Fore.BLUE}Mysql Finded!{Style.RESET_ALL}")
                time.sleep(2)
                print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {Fore.BLUE}Trying to connect...!{Style.RESET_ALL}")
                time.sleep(1)
                print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {Fore.GREEN}Conexion Refused! No vulnerable{Style.RESET_ALL}")
            else:
                print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {Fore.BLUE}Mysql Finded!{Style.RESET_ALL}")
                time.sleep(2)
                print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {Fore.BLUE}Trying to connect...!{Style.RESET_ALL}")
                time.sleep(1)
                print(f"{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.YELLOW}Mysql Root has no password! Vulnerable{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Mysql Version: {Fore.RED}{version}{Style.RESET_ALL}")
                time.sleep(3)
            print(f"\n{Fore.YELLOW}*************************{Fore.GREEN}PORT SCANNING{Fore.YELLOW}*************************{Style.RESET_ALL}")
            time.sleep(0.5)
            time.sleep(1)
            print(f"\n{Fore.GREEN}Scanning 1-10000 Ports This will take mins please Be patiente!{Style.RESET_ALL}\n")
            time.sleep(0.5)
            Open_ports = self.Port_Scan()
            print(f"{Fore.GREEN}Total Open Ports{Style.RESET_ALL}: {Fore.CYAN}{len(Open_ports)}\n{Style.RESET_ALL}")
            time.sleep(0.2)
            for i in Open_ports:
                print(f"{Fore.GREEN}Open Port: {Fore.RED}{i}{Style.RESET_ALL}/{Fore.BLUE}{self.obtener_servicio(i)}{Style.RESET_ALL}")
                time.sleep(0.5)
            time.sleep(0.5)
            
            print(f"\n{Fore.YELLOW}*************************{Fore.GREEN}PROCESSES{Fore.YELLOW}*************************{Style.RESET_ALL}")
            time.sleep(0.5)
            for i in psutil.process_iter():
                pid = i.pid
                nombre = i.name()
                usuario = i.username()
                try:
                    if psutil.Process(pid).is_running() and usuario == 'NT AUTHORITY\\SYSTEM': 
                        print(f"{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.RED}PID: {Fore.BLUE}{pid}, {Fore.GREEN}Process: {Fore.CYAN}{nombre}{Fore.YELLOW}{Fore.CYAN} Username: {Fore.GREEN}{usuario}, SUID (Admin): {Fore.RED}Sí{Style.RESET_ALL}")
                        time.sleep(0.1)
                    else:
                        print(f"{Fore.YELLOW}PID: {Fore.BLUE}{pid}, {Fore.YELLOW}Nombre: {Fore.GREEN}{nombre} {Fore.CYAN}Username: {Fore.GREEN}{usuario}, {Fore.YELLOW}SUID (Administrador): {Fore.GREEN}No{Style.RESET_ALL}")
                        time.sleep(0.1)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Manejar errores si no se puede acceder a la información del proceso
                    pass
            
            input(f"{Fore.CYAN}Press {Fore.GREEN}[ENTER]{Fore.CYAN} To continue{Style.RESET_ALL}")
                            
def animation():
    banner = Fore.RED + '''
              _____ _               _                 _____        __       
             / ____| |             | |               |_   _|      / _|      
            | (___ | |__   __ _  __| | _____      __   | |  _ __ | |_ ___   
             \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /   | | | '_ \|  _/ _ \  
             ____) | | | | (_| | (_| | (_) \ V  V /   _| |_| | | | || (_) | 
            |_____/|_| |_|\__,_|\__,_|\___/ \_/\_/   |_____|_| |_|_| \___/  

   _________________________________________________________________________________________
                                                                    
    '''
    banner2 = Fore.RED + '''\n\n\n
              _____ _               _                 _____        __       
             / ____| |             | |               |_   _|      / _|      
            | (___ | |__   __ _  __| | _____      __   | |  _ __ | |_ ___   
             \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /   | | | '_ \|  _/ _ \  
             ____) | | | | (_| | (_| | (_) \ V  V /   _| |_| | | | || (_) | 
            |_____/|_| |_|\__,_|\__,_|\___/ \_/\_/   |_____|_| |_|_| \___/  

   _________________________________________________________________________________________
                                                                    
    '''                                                           
    banner3 = Fore.RED + '''\n\n\n\n\n
              _____ _               _                 _____        __       
             / ____| |             | |               |_   _|      / _|      
            | (___ | |__   __ _  __| | _____      __   | |  _ __ | |_ ___   
             \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /   | | | '_ \|  _/ _ \  
             ____) | | | | (_| | (_| | (_) \ V  V /   _| |_| | | | || (_) | 
            |_____/|_| |_|\__,_|\__,_|\___/ \_/\_/   |_____|_| |_|_| \___/  

   _________________________________________________________________________________________
                                                                    
    '''
    os.system("cls")
    print(banner)
    time.sleep(0.4)
    os.system("cls")
    print(banner2)
    time.sleep(0.4)
    os.system("cls")
    print(banner)
    time.sleep(0.4)
    os.system("cls")
    print(banner3)
    time.sleep(0.4)
    os.system("cls")
    print(banner)
    time.sleep(0.4)
    os.system("cls")    

class CommandSection():
    def  __init__(self) -> None:
        self.Menu()
        pass

    def killPid(self, Pid):
        finded = False
        try:
            for i in psutil.process_iter():
                if int(Pid) == int(i.pid):
                    name = i.name()
                    os.kill(i.pid,signal.SIGTERM)
                    finded = True
                    return name
            
            if finded == False:
                return False
        except:
            return "Error"
    
    def ping_scan(self):
        ips = []
        macs = []
        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IpRange), timeout=2,verbose=0)
            for snd, rcv in ans:
                mac = r"%Ether.src%"
                ip = r"%ARP.psrc%"
                mac = rcv.sprintf(mac)
                ip = rcv.sprintf(ip)
                ips.append(ip)
                macs.append(mac.upper())
        except:
            pass
        return ips,macs

    def KillProcessByName(self,Name):
        founded = False
        pid = 0
        for i in psutil.process_iter():
            if str(i.name()) == str(Name):
                os.kill(i.pid,signal.SIGTERM)
                founded = True
                pid = i.pid
        if founded == True:
            return pid
        else:
            return False
    
    def Check_For_Conexions(self):
        for conn in psutil.net_connections(kind='inet'):
            try:
                if conn.raddr[0] != "127.0.0.1":
                    if str(conn.status) == "ESTABLISHED":
                        
                        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                        sess = re.match(ipv4_pattern,conn.raddr[0])
                        s = PcInfo(False)
                        data = s.Ip_Info(conn.raddr[0])
                     
                        if sess:
                            print(f"{Fore.GREEN}Dirección remota: {Fore.RED}{conn.raddr[0]}{Style.RESET_ALL}-{Fore.YELLOW}{conn.raddr[1]}{Style.RESET_ALL}")
                            print(f"{Fore.GREEN}Estado: {Fore.GREEN}", conn.status + Style.RESET_ALL)
                            print(f"\n   |   {Fore.YELLOW}IP INFO - {conn.raddr[0]}{Style.RESET_ALL}  ")
                            time.sleep(0.2)
                            
                            if data:
                                print(f"   ---- {Fore.GREEN}Hostname{Style.RESET_ALL} : {Fore.MAGENTA}{data.get('hostname', 'N/A')}{Style.RESET_ALL}")
                                time.sleep(0.2)
                                print(f"   |   ")
                                time.sleep(0.2)
                                print(f"   ---- {Fore.GREEN}Ubicación{Style.RESET_ALL}: {Fore.YELLOW}{data.get('city', 'N/A')}{Style.RESET_ALL}, {Fore.BLUE}{data.get('region', 'N/A')}{Style.RESET_ALL}, {Fore.CYAN}{data.get('country', 'N/A')}{Style.RESET_ALL}")
                                time.sleep(0.2)
                                print(f"   |   ")
                                time.sleep(0.2)
                                print(f"   ---- {Fore.GREEN}Proveedor de servicios de Internet ({Fore.YELLOW}ISP{Fore.GREEN}){Style.RESET_ALL}: {Fore.CYAN}{data.get('org', 'N/A')}{Style.RESET_ALL}")
                                time.sleep(0.2)
                                print(f"   |   ")
                                time.sleep(0.2)
                                print(f"   ---- {Fore.GREEN}Postal: {Style.RESET_ALL}: {Fore.CYAN}{data.get('postal', 'N/A')}{Style.RESET_ALL}")
                                time.sleep(0.2)
                                print(f"   |   ")
                                time.sleep(0.2)
                                print(f"   ---- {Fore.GREEN}Loc: {Style.RESET_ALL}: {Fore.CYAN}{data.get('loc', 'N/A')}{Style.RESET_ALL}\n")

                                with open("ConexionIp.txt","a") as file:
                                    file.write(f'''
---- Hostname : {data.get('hostname', 'N/A')}
|
---- Ubicación: {data.get('city', 'N/A')}, {data.get('region', 'N/A')}, {data.get('country', 'N/A')}
|
---- Proveedor de servicios de Internet (ISP): {data.get('org', 'N/A')}
|
---- Postal: : {data.get('postal', 'N/A')}
|
---- Loc: : {data.get('loc', 'N/A')}
''')
                                    file.close()
            
            except Exception as e:
                pass
        print(f"\n{Fore.GREEN}Saves to ConexionIp.txt!{Style.RESET_ALL}")
        time.sleep(2)

    def get_startup_programs(self):
        startup_programs = []

        # Clave del Registro que contiene las aplicaciones de inicio
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")

        try:
            index = 0
            while True:
                # Lee el valor del registro (nombre y ruta del programa)
                name, value, _ = winreg.EnumValue(key, index)
                startup_programs.append((name, value))
                index += 1
        except WindowsError:
            pass

        winreg.CloseKey(key)
        return startup_programs

    def find_process(self,Value):
        Value = str(Value)
        finded = False
        if Value.isdigit():
            for i in psutil.process_iter():
                if i.pid == int(Value):
                    print(F"[{Fore.GREEN}+{Style.RESET_ALL}] Process Finded With Name:{Fore.CYAN}{i.pid}-{i.name()}{Style.RESET_ALL}")
                    time.sleep(0.5)
                    finded = True
        else:
            for i in psutil.process_iter():
                if i.name() == Value:
                    print(F"[{Fore.GREEN}+{Style.RESET_ALL}] Process Finded With pID:{Fore.CYAN}{i.pid}-{i.name()}{Style.RESET_ALL}")
                    time.sleep(0.5)
                    finded = True
        
        if finded == False:
            print(F"[{Fore.RED}-{Style.RESET_ALL}] Couldnt find Process or Pid {Fore.YELLOW}{Value}{Style.RESET_ALL}")

    def find_mac_manufacturer(self,mac_address):
        formatted_mac = ':'.join(mac_address[i:i+2] for i in range(0, len(mac_address), 2))

        # Consultar la base de datos OUI del IEEE
        url = f'https://api.macvendors.com/{formatted_mac}'
        
        try:
            response = requests.get(url)
            if response.status_code == 200:
                manufacturer = response.text
                return manufacturer
            else:
                return f'N/A'
        except Exception as e:
            return f'Error'

    def Menu(self):
        while True:
            import platform
            name = platform.uname().node
            print(f'''\n
{Fore.CYAN}Hello : {Fore.GREEN}{name} {Fore.YELLOW}{datetime.now().hour}:{datetime.now().minute}{Style.RESET_ALL}

        [{Fore.GREEN}1{Style.RESET_ALL}] - {Fore.CYAN} Kill Process {Style.RESET_ALL}
        [{Fore.GREEN}2{Style.RESET_ALL}] - {Fore.CYAN} See IPV4 Information (Own or other){Style.RESET_ALL}
        [{Fore.GREEN}3{Style.RESET_ALL}] - {Fore.CYAN} Analyze current Conexions{Style.RESET_ALL}
        [{Fore.GREEN}4{Style.RESET_ALL}] - {Fore.CYAN} See All STARTUP aplications{Style.RESET_ALL}
        [{Fore.GREEN}5{Style.RESET_ALL}] - {Fore.CYAN} Scan Local network {Style.RESET_ALL}
        [{Fore.GREEN}6{Style.RESET_ALL}] - {Fore.CYAN} Find Process {Style.RESET_ALL}
        [{Fore.GREEN}7{Style.RESET_ALL}] - {Fore.YELLOW} Go back{Style.RESET_ALL}
        [{Fore.GREEN}8{Style.RESET_ALL}] - {Fore.RED} Exit {Style.RESET_ALL}
        ''')
            session = int(input(f"{Fore.GREEN}Select{Style.RESET_ALL}({Fore.CYAN}1{Style.RESET_ALL}-{Fore.CYAN}8{Style.RESET_ALL}): "))
            if session == 1:
                session = str(input(f"\n{Fore.GREEN}Enter Process {Fore.CYAN}name {Style.RESET_ALL}or {Fore.CYAN}Pid (PUT EXTENSIONS! ){Style.RESET_ALL}: "))
                if session.isdigit():
                    s = self.killPid(int(session))
                    if s == False:
                        print(f"{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.YELLOW} No process with Pid:{Fore.CYAN} {session}{Style.RESET_ALL}")
                        time.sleep(0.2)
                        input(f"\n{Fore.CYAN}Press {Fore.GREEN}[ENTER]{Fore.CYAN} To continue{Style.RESET_ALL}")
                        os.system("cls")
                    else:
                        print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {Fore.BLUE}Succesfully process Killed! ({Fore.CYAN}{s}{Style.RESET_ALL}{Fore.BLUE}) {Style.RESET_ALL}")
                        time.sleep(0.2)
                        input(f"\n{Fore.CYAN}Press {Fore.GREEN}[ENTER]{Fore.CYAN} To continue{Style.RESET_ALL}")
                        os.system("cls")

                else:   
                    s = self.KillProcessByName(session)
                    if s ==  False:
                        print(f"{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.YELLOW} No process with Name:{Fore.CYAN} {session}{Style.RESET_ALL}")
                        time.sleep(0.2)
                        input(f"\n{Fore.CYAN}Press {Fore.GREEN}[ENTER]{Fore.CYAN} To continue{Style.RESET_ALL}")
                        os.system("cls")
                    else:
                        print(f"[{Fore.GREEN}+{Style.RESET_ALL}] {Fore.BLUE}Succesfully process Killed! ({Fore.CYAN}{session} - {s}{Fore.BLUE}) {Style.RESET_ALL}")
                        time.sleep(0.2)
                        input(f"\n{Fore.CYAN}Press {Fore.GREEN}[ENTER]{Fore.CYAN} To continue{Style.RESET_ALL}")
                        os.system("cls")
            
            elif session == 2:
                s = PcInfo(False)
                Ip = input(f"{Fore.BLUE}Enter ipv4 (Or Own) : {Fore.RED}")
                print(Style.RESET_ALL)
                if Ip == "Own":
                    own_ip = s.ipv4()
                    data = s.Ip_Info(own_ip)

                    print(f"\n   |   {Fore.YELLOW}IP INFO - {own_ip}{Style.RESET_ALL}  ")
                    time.sleep(0.2)
                    
                    if data:
                        print(f"   ---- {Fore.GREEN}Hostname{Style.RESET_ALL} : {Fore.MAGENTA}{data.get('hostname', 'N/A')}{Style.RESET_ALL}")
                        time.sleep(0.2)
                        print(f"   |   ")
                        time.sleep(0.2)
                        print(f"   ---- {Fore.GREEN}Ubicación{Style.RESET_ALL}: {Fore.YELLOW}{data.get('city', 'N/A')}{Style.RESET_ALL}, {Fore.BLUE}{data.get('region', 'N/A')}{Style.RESET_ALL}, {Fore.CYAN}{data.get('country', 'N/A')}{Style.RESET_ALL}")
                        time.sleep(0.2)
                        print(f"   |   ")
                        time.sleep(0.2)
                        print(f"   ---- {Fore.GREEN}Proveedor de servicios de Internet ({Fore.YELLOW}ISP{Fore.GREEN}){Style.RESET_ALL}: {Fore.CYAN}{data.get('org', 'N/A')}{Style.RESET_ALL}")
                        time.sleep(0.2)
                        print(f"   |   ")
                        time.sleep(0.2)
                        print(f"   ---- {Fore.GREEN}Postal: {Style.RESET_ALL}: {Fore.CYAN}{data.get('postal', 'N/A')}{Style.RESET_ALL}")
                        time.sleep(0.2)
                        print(f"   |   ")
                        time.sleep(0.2)
                        print(f"   ---- {Fore.GREEN}Loc: {Style.RESET_ALL}: {Fore.CYAN}{data.get('loc', 'N/A')}{Style.RESET_ALL}\n")
                        input(f"\n{Fore.CYAN}Press {Fore.GREEN}[ENTER]{Fore.CYAN} To continue{Style.RESET_ALL}")
                        os.system("cls")
                        
                else:
                    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                    sess = re.match(ipv4_pattern,Ip)

                    if sess:
                        data = s.Ip_Info(Ip)

                        print(f"\n   |   {Fore.YELLOW}IP INFO - {Ip}{Style.RESET_ALL}  ")
                        time.sleep(0.2)
                        
                        if data:
                            print(f"   ---- {Fore.GREEN}Hostname{Style.RESET_ALL} : {Fore.MAGENTA}{data.get('hostname', 'N/A')}{Style.RESET_ALL}")
                            time.sleep(0.2)
                            print(f"   |   ")
                            time.sleep(0.2)
                            print(f"   ---- {Fore.GREEN}Ubicación{Style.RESET_ALL}: {Fore.YELLOW}{data.get('city', 'N/A')}{Style.RESET_ALL}, {Fore.BLUE}{data.get('region', 'N/A')}{Style.RESET_ALL}, {Fore.CYAN}{data.get('country', 'N/A')}{Style.RESET_ALL}")
                            time.sleep(0.2)
                            print(f"   |   ")
                            time.sleep(0.2)
                            print(f"   ---- {Fore.GREEN}Proveedor de servicios de Internet ({Fore.YELLOW}ISP{Fore.GREEN}){Style.RESET_ALL}: {Fore.CYAN}{data.get('org', 'N/A')}{Style.RESET_ALL}")
                            time.sleep(0.2)
                            print(f"   |   ")
                            time.sleep(0.2)
                            print(f"   ---- {Fore.GREEN}Postal: {Style.RESET_ALL}: {Fore.CYAN}{data.get('postal', 'N/A')}{Style.RESET_ALL}")
                            time.sleep(0.2)
                            print(f"   |   ")
                            time.sleep(0.2)
                            print(f"   ---- {Fore.GREEN}Loc: {Style.RESET_ALL}: {Fore.CYAN}{data.get('loc', 'N/A')}{Style.RESET_ALL}\n")
                            input(f"\n{Fore.CYAN}Press {Fore.GREEN}[ENTER]{Fore.CYAN} To continue{Style.RESET_ALL}")
                            os.system("cls")
                    else:
                        print(f"{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}] {Fore.YELLOW} Enter a Valid IPV4! {Style.RESET_ALL}")
            elif session == 3:
                os.system("cls")
                self.Check_For_Conexions()
            
            elif session == 4:
                startup = self.get_startup_programs()
                if startup:
                    print(f"\n{Fore.YELLOW}----------------------------------------------{Fore.BLUE}STARTUP APLICATIONS{Fore.YELLOW}----------------------------------------------")
                    for name,rute in startup:
                        print(f"\n{Fore.GREEN}File Name: {Fore.CYAN}{name}{Style.RESET_ALL}-{Fore.BLUE}{rute}{Style.RESET_ALL}")
                        time.sleep(0.5)

                input(f"\n{Fore.CYAN}Press {Fore.GREEN}[ENTER]{Fore.CYAN} To continue{Style.RESET_ALL}\n")
                os.system("cls")
            elif session == 5:
                ips,mac = self.ping_scan()
                print(f"\n{Fore.YELLOW}IPV4\t\t\t{Fore.BLUE}MAC ADDRESS{Style.RESET_ALL}\t\t\t{Fore.GREEN}Manufacter{Style.RESET_ALL}\n")
                for i in range(len(ips)):
                    print(f"{Fore.CYAN}{ips[i]}\t\t{Fore.RED}{mac[i]}\t\t{Fore.GREEN}{self.find_mac_manufacturer(mac[i])}{Style.RESET_ALL}")
                    time.sleep(0.5)
                
                input(f"\n{Fore.CYAN}Press {Fore.GREEN}[ENTER]{Fore.CYAN} To continue{Style.RESET_ALL}\n")
                os.system("cls")

            elif session == 6:
                session = str(input(f"\n{Fore.GREEN}Enter Process {Fore.CYAN}name {Style.RESET_ALL}or {Fore.CYAN}Pid (PUT EXTENSIONS! ){Style.RESET_ALL}: "))

                self.find_process(session)

                input(f"\n{Fore.CYAN}Press {Fore.GREEN}[ENTER]{Fore.CYAN} To continue{Style.RESET_ALL}\n")
                os.system("cls")

            elif session == 7:
                os.system("cls")
                iniciar()
                break
                
            elif session == 8:
                sys.exit(0)


def iniciar():
    if __name__ == "__main__":
        try:
            if platform.system() != "Windows":
                print(f"\n{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}]{Fore.CYAN} {platform.system()} Is not supported, Run this program in Windows! {Style.RESET_ALL}")
                sys.exit(1)
            try:
                if ctypes.windll.shell32.IsUserAnAdmin() ==  1:
                    pass
                else:
                    print(f"\n{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}]{Fore.CYAN} Run The program as Administrator! {Style.RESET_ALL}")
                    sys.exit(1)
            except:
                print(f"\n{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}]{Fore.CYAN} Run The program as Administrator! {Style.RESET_ALL}")
                sys.exit(1)
            while True:
                name = platform.uname().node
                os.system("title Shadow Info")
                time.sleep(0.5)
                Menu = print(f'''
{Fore.CYAN}Hello : {Fore.GREEN}{name} {Fore.YELLOW}{datetime.now().hour}:{datetime.now().minute}{Style.RESET_ALL}

            [{Fore.GREEN}1{Style.RESET_ALL}] - {Fore.CYAN} Analyze system searching for vulnerabilities and information {Style.RESET_ALL}
            [{Fore.GREEN}2{Style.RESET_ALL}] - {Fore.CYAN} Command Section (Killing processes etc) {Style.RESET_ALL}
            [{Fore.GREEN}3{Style.RESET_ALL}] - {Fore.CYAN} Discord / Github{Style.RESET_ALL}
            [{Fore.GREEN}4{Style.RESET_ALL}] - {Fore.RED} Exit {Style.RESET_ALL}
        ''')
                session = int(input(f"{Fore.GREEN}Select{Style.RESET_ALL}({Fore.CYAN}1{Style.RESET_ALL}-{Fore.CYAN}4{Style.RESET_ALL}): "))
                if session == 1:
                    PcInfo(True)
                elif session == 2:
                    os.system("cls")
                    CommandSection()
                elif session == 3:
                    print(f"{Fore.CYAN}Discord Name: {Fore.GREEN}Shadow_da352ni.{Style.RESET_ALL}")
                    url_invitacion = 'https://discord.gg/uuaRc5VP'
                    url2_github = "https://github.com/ivanlr-design"
                    webbrowser.open(url_invitacion)
                    webbrowser.open(url2_github)
                    input(f"{Fore.CYAN}Press {Fore.GREEN}[ENTER]{Fore.CYAN} To continue{Style.RESET_ALL}")
                    os.system("cls")
                elif session == 4:
                    sys.exit(0)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[{Fore.RED}!{Fore.YELLOW}]{Fore.CYAN} Operation canceled by User! {Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"Followed Error: {str(e)}")
            sys.exit(1)
animation()
iniciar()

