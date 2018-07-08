# -*-coding:utf-8 -*-

fp = open('../firewall.log','r')
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

ip=['188.18.109.220', '187.205.239.58', '188.18.109.178', '190.153.50.5', '205.240.83.113', '200.96.202.149','190.12.110.198', '201.105.140.65', '189.101.254.77', '190.154.212.234', '188.18.252.214', '187.227.61.204', '189.103.81.30', '188.18.254.191', '188.18.110.213', '189.107.159.211', '190.16.153.49', '187.243.105.125', '187.250.101.20', '189.1.48.108', '190.113.88.71', '187.38.17.95']#송신자 ip
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
            '''inq=True
            if temp in ip:
                inx=ip.index(temp)
                continue
            ip.append(temp)#ip리스트에 없으면 추가
            le.append(0)
            inx=ip.index(temp)'''
            if temp in ip:
                continue
            print temp
            

print ip
print le