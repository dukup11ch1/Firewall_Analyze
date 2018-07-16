# -*-coding:utf-8 -*-
import pymysql

fp = open('../firewall.log','r')#open log file
def read_space(): 
    a=fp.read(1024*1024*1024)#1GB read
    while True:#after 1GB read, search breakpoint
        b=fp.read(1)
        a=a+b
        if b==' ':
            b=fp.read(1)
            if b=='2':
                fp.seek(-1,1)
                del b
                return a
            a=a+b

conn = pymysql.connect(host='localhost',
    user='root',
    password='root',
    charset='utf8mb4')#mysql connect
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
    cursor.execute(sql)#db reset



with conn.cursor() as cursor:#create table
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
    del a
    #2018-06-28 08:09:33 fl0ckfl0ck_info id=3087 severity=info sys=SecureNet sub=Packetfilter name=Packet Accepted action=Accepted fwrule=90 src_mac=b8:ae:ed:7b:56:73 dst_mac=26:3a:ca:22:d1:bf src_ip=181.141.148.69 dst_ip=188.18.109.220 length=3808 srcport=20064 dst_port=23
    #18 variables
    #index-> 18*a+subindex
    for i in xrange(len(b)/18):
        if b[18*i+17] != '175.45.178.3':#push only bad ip
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
        del time
        del src_ip
        del dst_ip
        del src_mac
        del dst_mac
        del length
        del src_port
        del dst_port
        del temp
        del ttemp
    #delete variables for memory
    del b
    
conn.close()