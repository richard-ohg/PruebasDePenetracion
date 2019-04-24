# PORT SCANNER
# Modo de uso:
# sudo python3 port_scanner.py -t ip -s syn/xmas/udp -p puerto1 puerto2
import optparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

 
def print_ports(port, state):
	'''
		Función para imprimir con formato los puertos.
		port: puerto a imprimir
		state: estado de ese puerto
	'''
	print("{} | {}".format(port, state))

def syn_scan(target, ports):
	'''
		Función para hacer escaneo syn-ack
		target: ip destino
		ports: lista de puertos a escanear
	'''
	print("syn scan on, {} with ports {}".format(target, ports))
	# Generamos un puerto aleatorio para salir 
	sport = RandShort()
	print("puerto de origen: ", sport)
	# Recorremos la lista de puertos a escanear
	for port in ports:
		# Generamos el paquete que vamos a enviar con bandera 'S'
		package = IP(dst=target)/TCP(sport=sport, dport=port, flags="S")
		# Mandamos el paquete 
		response = sr1(package, timeout=10, verbose=0)
		print(response)
		print(type(response))
		print(str(type(response)))
		# Checamos que tenemos respuesta
		if response != None:
    		# Verificamos que tenga cabecera TCP
			if response.haslayer(TCP):
    			# Si nos regresa una bandera RES
				if response[TCP].flags == 0x14:
					print_ports(port, "Closed")
				# Si nos regresa una bandera SYN-ACK
				elif response[TCP].flags == 0x12:
					print_ports(port, "Open")
				else:
					print_ports(port, "TCP packet resp / filtered")
			elif response.haslayer(ICMP):
				print_ports(port, "ICMP resp / filtered")
			else:
				print_ports(port, "Unknown resp")
				print(response.summary())
		else:
			print_ports(port, "Unanswered")


def udp_scan(target, ports):
	'''
		Función para hacer un escaneo por udp
		target: ip destino
		ports: lista de puertos a escanear
	'''
	print("udp scan on, {} with ports {}".format(target, ports))
	# Generamos un puerto aleatorio para salir 
	sport = RandShort()
	for port in ports:
		# Generamos paquete
		package = IP(dst=target)/UDP(sport=sport, dport=port)
		# Lo enviamos y recibimos respuesta con sr1()
		response = sr1(package, timeout=10, verbose=0)
		# Checamos si la respuesta está vacía
		if response == None:
			print_ports(port, "Open / filtered")
		else:
			if response.haslayer(ICMP):
				print_ports(port, "Closed")
			elif response.haslayer(UDP):
				print_ports(port, "Open / filtered")
			else:
				print_ports(port, "Unknown")
				print(response.summary())


def xmas_scan(target, ports):
	'''
		Función para hacer un escaner xmas
		target: ip destino
		ports: lista de puertos a escanear
	'''
	print("Xmas scan on, %s with ports %s" %(target, ports))
	# Generamos un puerto aleatorio para salir 
	sport = RandShort()
	for port in ports:
		package = IP(dst=target)/TCP(sport=sport, dport=port, flags="FPU")
		response = sr1(package, timeout=10, verbose=0)
		if response != None:
			if response.haslayer(TCP):
				if response[TCP].flags == 0x14:
					print_ports(port, "Closed")
				else:
					print_ports(port, "TCP flag %s" % response[TCP].flag)
			elif response.haslayer(ICMP):
				print_ports(port, "ICMP resp / filtered")
			else:
				print_ports(port, "Unknown resp")
				print(response.summary())
		else:
			print_ports(port, "Open / filtered")

def opciones():
	'''
		Función para obtener las opciones que elija el usuario
	'''
	parser = argparse.ArgumentParser("Port scanner using Scapy")
	parser.add_argument("-t", "--target", help="Specify target IP", required=True)
	parser.add_argument("-p", "--ports", type=int, nargs="+", help="Specify ports (21 23 80 ...)")
	parser.add_argument("-s", "--scantype", help="Scan type, syn/udp/xmas", required=True)
	args = parser.parse_args()
	return args


if __name__ == '__main__':
	# Obtenemos las opciones
	args = opciones()
	# Las guardamos en variables auxiliares
	target = args.target
	scantype = args.scantype.lower()

	# En caso de no tener puertos, se escanean los primeros 1024
	if args.ports:
		ports = args.ports
	else:
		ports = range(1, 1024)

	# Formato a la salida
	conf.color_theme = ColorOnBlackTheme()
	# Verificamos que que tipo de escaneo se pidió
	if scantype == "syn" or scantype == "s":
		syn_scan(target, ports)
	elif scantype == "udp" or scantype == "u":
		udp_scan(target, ports)
	elif scantype == "xmas" or scantype == "x":
		xmas_scan(target, ports)
	else:
		print("Scan type not supported")