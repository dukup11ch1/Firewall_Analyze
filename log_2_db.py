# -*-coding:utf-8 -*-
import pymysql

fp = open('../firewall.log','r')#파일 읽어옴
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

conn = pymysql.connect(host='localhost',
    user='root',
    password='root',
    charset='utf8mb4')#mysql연결
try :
    with conn.cursor() as cursor:
        sql='DROP DATABASE firewall'
        cursor.execute(sql)
except:
    pass

with conn.cursor() as cursor:
    sql = 'CREATE DATABASE firewall'
    cursor.execute(sql)
    sql = 'USE firewall'
    cursor.execute(sql)#db 초기화



with conn.cursor() as cursor:#테이블 생성
    sql = '''
        CREATE TABLE firewall (
            id int(255) NOT NULL AUTO_INCREMENT PRIMARY KEY,
            time bigint(255) NOT NULL,
            src_mac varchar(255) NOT NULL,
            dst_mac varchar(255) NOT NULL,
            src_ip bigint(255) NOT NULL,
            dst_ip bigint(255) NOT NULL,
            length int(255) NOT NULL,
            src_port int(255) NOT NULL,
            dst_port int(255) NOT NULL
        ); 
        '''
    cursor.execute(sql)

while True:
    try:
        a=""
        a=read_space()
    except:
        break
    b=a.split(" ")
    #2018-06-28 08:09:33 fl0ckfl0ck_info id=3087 severity=info sys=SecureNet sub=Packetfilter name=Packet Accepted action=Accepted fwrule=90 src_mac=b8:ae:ed:7b:56:73 dst_mac=26:3a:ca:22:d1:bf src_ip=181.141.148.69 dst_ip=188.18.109.220 length=3808 srcport=20064 dst_port=23
    #총 종류 18개
    #index-> 18*a+subindex
    for i in xrange(len(b)/18):
        if b[18*i+17] != '175.45.178.3':#미리 찾은 ip만 찾아 디비에 넣기 위함
            continue
        time=int(b[18*i].replace("-","")+b[18*i+1].replace(":",""))
        src_mac=b[18*i+11].split('=')[1]
        dst_mac=b[18*i+12].split('=')[1]
        temp=b[18*i+13].split('=')[1]
        ttemp=temp.split('.')
        src_ip=int(ttemp[0])*16777216+int(ttemp[1])*65536+int(ttemp[2])*256+int(ttemp[3])
    
        temp=b[18*i+14].split('=')[1]
        ttemp=temp.split('.')
        dst_ip=int(ttemp[0])*16777216+int(ttemp[1])*65536+int(ttemp[2])*256+int(ttemp[3])
    
        length=int(b[18*i+15].split('=')[1])
    
        src_port=int(b[18*i+16].split('=')[1])
    
        dst_port=int(b[18*i+17].split('=')[1])
        with conn.cursor() as cursor:
            sql = 'INSERT INTO firewall (time, src_mac,dst_mac,src_ip,dst_ip,length,src_port,dst_port) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)'#db에 넣어줌
            cursor.execute(sql, (time, src_mac,dst_mac,src_ip,dst_ip,length,src_port,dst_port))
        conn.commit()
    del a#메모리 최적화를 위한 변수 삭제
    del b
    
conn.close()