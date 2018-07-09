# -*-coding:utf-8-*-
import pymysql

fp = open('firewall.log','r')
def read_space(): #한 줄 읽기
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
conn = pymysql.connect(host='localhost',#mysql연결
    user='root',
    password='root',
    charset='utf8mb4')
try :#mysql 삭제
    with conn.cursor() as cursor:
        sql='DROP DATABASE firewall'
        cursor.execute(sql)
except:
    pass

with conn.cursor() as cursor:#mysql db만들기
    sql = 'CREATE DATABASE firewall'
    cursor.execute(sql)
    sql = 'USE firewall'
    cursor.execute(sql)



with conn.cursor() as cursor:#mysql table 만들기
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
        a=read_space()
    except:
        break
    b=a.split(" ")
    time = b[0]+b[1]
    time=time.replace(":","")
    time=time.replace("-","")
    time=int(time)
    src_mac=dst_mac=src_ip=dst_ip=length=src_port=dst_port=""
    for s in b:#데이터 나누기
        if "src_mac" in s:
            src_mac=s.split('=')[1]
        if "dst_mac" in s:
            dst_mac=s.split('=')[1]
        if "src_ip" in s:
            temp=s.split('=')[1]
            ttemp=temp.split('.')
            src_ip=int(ttemp[0])*16777216+int(ttemp[1])*65536+int(ttemp[2])*256+int(ttemp[3])#비트를 전부 이어서 int화
        if "dst_ip" in s:
            dst_ip=s.split('=')[1]
        if "length" in s:
            length=int(s.split('=')[1])
        if "srcport" in s:
            src_port=int(s.split('=')[1])
        if "dst_port" in s:
            dst_port=int(s.split('=')[1])
    if dst_ip =='175.45.178.3':
        ttemp=temp.split('.')
        dst_ip=int(ttemp[0])*16777216+int(ttemp[1])*65536+int(ttemp[2])*256+int(ttemp[3])
    else :
        continue
    with conn.cursor() as cursor:
        sql = 'INSERT INTO firewall (time, src_mac,dst_mac,src_ip,dst_ip,length,src_port,dst_port) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)'#sql에 넣음
        cursor.execute(sql, (time, src_mac,dst_mac,src_ip,dst_ip,length,src_port,dst_port))
    conn.commit()
    
conn.close()