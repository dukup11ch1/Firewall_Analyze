# -*-coding:utf-8 -*-

fp = open('firewall.log','r')
def read_space(): #한 줄 
    a=""
    while True:
        b=fp.read(1)
        a=a+b
        if b==' ':
            b=fp.read(1)
            if b=='2':
                fp.seek(-1,1)
                break
            a=a+b

    return a

ip=[]
le=[]
inq=False
inx=0
while True:
    try:
        a=read_space()
    except:
        break
    b=a.split(" ")
    for s in b:
        if "dst_ip" in s:
            temp=s.split('=')[1]
            inq=True
            if temp in ip:
                inx=ip.index(temp)
                continue
            ip.append(temp)
            le.append(0)
            inx=ip.index(temp)
        if "length" in s:
            if inq:
                inq=False
                le[inx]+=int(s.split('=')[1])

print ip
print le