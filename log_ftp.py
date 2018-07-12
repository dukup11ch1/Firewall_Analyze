# -*-coding:utf-8 -*-

fp = open('../firewall.log','r')
def read_space(): 
    a=fp.read(1024*1024*1024)#1GB씩 읽는다
    while True:#1GB읽고 끊을 지점 탐색
        b=fp.read(1)
        a=a+b
        if b==' ':
            b=fp.read(1)
            if b=='2':
                fp.seek(-1,1)
                return a
            a=a+b

ip=[]#송신자 ip
le=[]#ip별 전체 길이
inq=False#송신자 ip 중복검사
inx=0#인덱스
while True:
    try:#읽다가 안읽힘(EOF 예외발생)시 그만 읽기 위해 예외처리
        a=read_space()
    except:
        break
    b=a.split(" ")
    for i in xrange(len(b)/18):
        temp=b[18*i+17].split('=')[1]
        if temp in ip:
            inx=ip.index(temp)
            continue
        ip.append(temp)#ip리스트에 없으면 추가
        le.append(0)
        inx=ip.index(temp)
        le[inx]+=int(b[18*i+15])#length 계산

            
print ip
print le