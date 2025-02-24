import socket

def scan_port(target, ports=[21, 22, 80, 433, 3306]):
    
    open_ports = []
    print(f"\n\t==============Sacn des ports sur -->{target}<-- 🔍 ==============\n")
    
    for port in ports :
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        if sock.connect_ex((target, port)) == 0:
            print(f"---> {port} OUVERT *** :) ")
            open_ports.append(port)
        else:
            print(f"---> {port} FERME *** :( ")
        sock.close
    
    return open_ports

if __name__ == "__main__":
    target_ip = input(" Entre un IP : ")
    scan_port(target_ip)