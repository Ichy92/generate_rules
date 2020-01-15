# import csv
import sys
import json

# def GetAllData_(f):
#     reader=csv.reader(f)
#     listTmp=[]
#     for row in reader:
#         listTmp.append(row)
#     return listTmp
 

import pandas as pd
import numpy as np
 
def GetAllData(f):
    df = pd.read_csv(f, sep=";")
    print(df.head())
#     df = df[:5000]
#     df_t = df.T
    xx = df.to_numpy()
    print(xx)
    return xx
    
    

def GetListTmp_1(listData):
            listTmp=[]
            for i in range(0,len(listData)):
                listTmp.append([listData[i][2],listData[i][3],listData[i][5],listData[i][6]])
            return listTmp

def GetListTmp_2(listData):
            listTmp=[]
            for i in range(0,len(listData)):
                listTmp.append([listData[i][2],listData[i][3],listData[i][5]])
            return listTmp

def CheckSama(data,L2):
        status=False
        for i in L2:
                    if data==i:
                                status=True
        return status

def HitungSama(data,List):
            jml=0
            for i in List:
                        if data==i:
                                    jml=jml+1
            return jml

def Sisa_Data(List,List_Id_used):
            hasil=list()
            for i in List:
                            if i[0] not in List_Id_used:
                                            hasil.append(i)
            return hasil

def Final_Check(data,ListHasilAkhirTmp):
            for i in ListHasilAkhirTmp:
                            if data==[i[1],i[2],i[3],i[6]]:
                                            return 1
            return 0
            
#open data
#f=open('UDPPortScan3(1)','rb')
#master_data=GetAllData(f)
master_data=GetAllData('databaru.csv')
ListData=list(master_data)

L1=GetListTmp_1(ListData)
L2=list(L1)



ListFinal=list()
ListFinalTmp=list()
id_used=list()
def find_id_used():
    for idx, i in enumerate(L1):
        if idx %1000 == 0:
            if idx %5000 == 0:
                print(idx)
            else:
                print(idx, end="")
        else:
            if idx %100 == 0:
                print(".", end="")
        if HitungSama(i,L2) >1:
            id_used.append(ListData[idx][0])
            if [i[0],i[1],i[2],i[3],str(HitungSama(i,L2))] not in ListFinalTmp:
                ListFinalTmp.append([i[0],i[1],i[2],i[3],str(HitungSama(i,L2))])

                ListFinal.append([ListData[idx][0],ListData[idx][2],ListData[idx][3],ListData[idx][5],ListData[idx][6],str(HitungSama(i,L2))])
                idx=idx+1
find_id_used()
print("find_id_used()")

ListData=Sisa_Data(ListData,id_used)
L1=GetListTmp_2(ListData)
L2=list(L1)

ListFinalTmp=list()

# idx=0
for idx, i in enumerate(L1):
    if idx %1000 == 0:
        print(idx)
    else:
        if idx %100 == 0:
            print(".", end="")
        
    if HitungSama(i,L2)>5:
        id_used.append(ListData[idx][0])
        if [i[0],i[1],i[2],str(HitungSama(i,L2))] not in ListFinalTmp:
            ListFinalTmp.append([i[0],i[1],i[2],str(HitungSama(i,L2))])

            ListFinal.append([ListData[idx][0],ListData[idx][2],ListData[idx][3
],ListData[idx][5],ListData[idx][6],str(HitungSama(i,L2))])
            idx=idx+1

L1=Sisa_Data(master_data,id_used)

for i in L1:
    ListFinal.append([i[0],i[2],i[3],i[5],i[6],'0'])

id_final=list()
for i in ListFinal:
    id_final.append(i[0])

id_final.sort(key=int)

HasilAkhir=list()
# idx=0
for idx, i in enumerate(id_final):
    if idx %1000 == 0:
        print(idx)
    else:
        if idx %100 == 0:
            print(".", end="")
    for j in ListFinal:
        if i==j[0]:
             HasilAkhir.append(j)
f_out=open("/etc/snort/rules/local.rules","w") #ubah a
print("local.rules open")

Tmp=[[0,0,0,0,0]]
Tmp2=list()
for i in HasilAkhir:
    if int(i[5])<=10:
        Tmp2.append([i[0],i[1],i[2],i[3],i[4],i[5],'0'])
    elif int(i[5])>10 :
        if [i[1],i[2],i[3]] not in Tmp:
            Tmp.append([i[1],i[2],i[3]])
            Tmp2.append([i[0],i[1],i[2],i[3],i[4],i[5],'1'])
    #else:
                            #inc=inc-1
    #inc=inc+1
print("hasil akhir")
Tmp=list()
Tmp=[0,0,0,0,0]

no=10000000
inc=1
   
def convert_msg(protocol, port):
    # print("#",protocol, port)
    if protocol == 'tcp':
        return "syn flood attact"
    elif protocol == 'tcp' and port == 80:
        return "sql injection"
    if protocol == "icmp":
        return "ping attack"
    else:
        print(protocol, port)
        # return "<possible attack>"
    
temp_ip = list()
temp_port = list()

with open('old_rules.json', 'r') as json_file:
    old_rules = json.load(json_file)
    
rules=list()
for i in Tmp2:
    if i[6]=='1':
        #print(i[4], i[1])
        Tmp.append([i[1],i[2],i[3]])
        rules.append('alert '+i[1]+' '+i[2]+' any -> '+str(i[3])+' '+str(i[4])+' any (msg: "'+convert_msg(i[1], int(i[4]))+'"; flags:S; thre$; threshold: type threshold, track by_dsr, count 1, second 60; sid:'+str(no+inc)+');rev: 1;\n')

        inc=inc+1
    else:
        if [i[1],i[2],i[3]] not in Tmp:
            rules.append('alert '+i[1]+' '+i[2]+' any -> '+str(i[3])+' '+str(i[4])+' any (msg: "'+convert_msg(i[1], int(i[4]))+'"; flags:S; thre$; threshold: type threshold, track by_dsr, count 1, second 60; sid:'+str(no+inc)+');rev: 1;\n')
        inc=inc+1
        
rules = list(set(old_rules+rules))
for rule in rules:
    f_out.write(rule)

with open('old_rules.json', 'w') as json_file:
    json.dump(rules,json_file)
print('Success!')

f_out.close()
