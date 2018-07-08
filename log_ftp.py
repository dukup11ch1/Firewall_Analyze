# -*-coding:utf-8 -*-

fp = open('firewall.log','r')
def read_space(): #스페이스 단위로 읽기위한 read 함수 새로만듦
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
    for s in b:
        if "dst_ip" in s:
            temp=s.split('=')[1]
            inq=True
            if temp in ip:
                inx=ip.index(temp)
                continue
            ip.append(temp)#ip리스트에 없으면 추가
            le.append(0)
            inx=ip.index(temp)
        if "length" in s:
            if inq:
                inq=False
                le[inx]+=int(s.split('=')[1])#length 계산

print ip
print le