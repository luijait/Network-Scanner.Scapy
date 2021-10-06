import scapy.all as scapy
#XANAX
print("Programita realizado por: 0x6c75696a616974")
rangodenet = input("Introduce con la siguiente mascara (192.168.1.1/24) la net que quieres escanear: ")
def escaneito(ip):
	request_arp = scapy.ARP(pdst=ip)
	difusion = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	request_difusion = difusion/request_arp
	respuestas = scapy.srp(request_difusion, timeout=1, verbose=False)[0]

	hosts_conectaos = []
	for respuesta in respuestas:
		hosts_dick = {"ip": respuesta[1].psrc, "mac": respuesta[1].hwsrc}
		hosts_conectaos.append(hosts_dick)
		return (hosts_conectaos)
def print_diccionario(escaneo):
	print("IP:\t\t\tDireccion Mac\n------------------------------------------")
	for host in escaneo_final:
		print(host["ip"] + "\t\t" + host["mac"])

escaneo_final = escaneito(rangodenet)
print_diccionario(escaneo_final)
