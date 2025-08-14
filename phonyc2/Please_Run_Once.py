import uuid

IP = input("Enter IP Address: ")  # Python 3
Port = input("Enter Port Number: ")  # Python 3
Ext = input("Enter WebServer Ext Like (Php|ASPX|JSP|HTML|ASP|) : ")  # Python 3
fin = open("isnotcore/config.bak", "rt")
data = fin.read()
#print(data)
for line in data:
    #read replace the string and write to output file
    data = data.replace('[IP]', IP)
    
    data = data.replace('[Port]', Port)

    data = data.replace('[Ext]', Ext)


    data = data.replace('[111]', str(uuid.uuid4()))
    data = data.replace('[222]', str(uuid.uuid4()))
    data = data.replace('[333]', str(uuid.uuid4()))
    data = data.replace('[444]', str(uuid.uuid4()))
    data = data.replace('[555]', str(uuid.uuid4()))
    data = data.replace('[666]', str(uuid.uuid4()))
    data = data.replace('[777]', str(uuid.uuid4()))
    data = data.replace('[888]', str(uuid.uuid4()))



fin.close()


fin1 = open("isnotcore/config.py", "wt")
#overrite the input file with the resulting data
fin1.write(data)
fin1.close()