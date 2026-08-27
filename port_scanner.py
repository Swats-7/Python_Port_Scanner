
import socket 
import concurrent
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime 
import sys 

target = input("Enter the target IP : ")
start_port = int(input("Which port to start scanning from : "))
end_port = int(input("Till which port to scan : "))

if start_port < 0 or end_port > 65535: 
    sys.exit("Input invalid")

socket.setdefaulttimeout(0.2)

def Scan(port) : 
    with socket.socket(socket.AF_INET , socket.SOCK_STREAM) as s :  
        result = s.connect_ex((target,port))
        if result == 0 : 
            try : 
                banner = s.recv(1024).decode()
                return f"Port {port} is open with banner {banner}"
            
            except : 
            
                return f"Port {port} is online "
        
        else : return 0 


print("scanning target " + target)
print("scan started at ",datetime.now() )
print("-"*50)

num_ports = 0 
total_ports = end_port-start_port

with ThreadPoolExecutor(max_workers= 100) as executor : 
    futures = {executor.submit(Scan,port) : port for port in range(start_port,end_port)}
    
    for future in concurrent.futures.as_completed(futures) :
        num_ports += 1 
        port = futures[future] 
        result = future.result()
        if num_ports%10 == 0 : 
            print(f"{num_ports} out of {total_ports} scanned") 

        if result != 0 : 
            print(result)


    

