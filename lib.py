import pandas as pd
import numpy as np
import numpy
import json

def to_str(data):
    data = list(data)
    for ix, i in enumerate(data):
        i = i.tolist()
        i[3]=str(i[3])
#         print(i)
        data[ix] = " ".join(i)
    return data

def find_used(df, batas_min = 5):
    df2 = df[['proto', 'source_ip', 'dest_ip', 'dest_port']]
    xx = df2.to_numpy()
    xx.tolist()
    data_str = to_str(xx)
    unik = list(set(data_str))

    counter = list()
    for u in unik:
        counter.append(data_str.count(u))

    index_final = list()
    for ix, i in enumerate(counter):
        if i >= batas_min:
            index_final.append(ix)

    final = np.array(unik)[index_final]
    return final


# with open('old_rules_.json', 'r') as f:
#     temp_rule = json.load(f)
# temp_rule = list()

# with open('sid.json', 'r') as f:
#     temp_sid = json.load(f)
    
# temp_sid = [10000]

def get_sid(sqlinjection_sid, selected_rule_sqlinjection):
    sqlinjection_sid_list =[x for x in range(sqlinjection_sid[-1], sqlinjection_sid[-1]+len(selected_rule_sqlinjection))]
    sqlinjection_sid_list = sqlinjection_sid + sqlinjection_sid_list
    return sqlinjection_sid_list

def make_rule(data, sid_list):
    result = list()
    for i in range(len(data)):
        sid = sid_list[i]
        rule_sid = data[i]+" sid:"+str(sid)+";\n"
        result.append(rule_sid)
    return result

def save_json(data, namafile):
    with open(namafile+'.json', 'w') as f:
        json.dump(data, f)
        
def open_json(nama_file):
    with open(nama_file+'.json', 'r') as f:
        temp_rule = json.load(f)
    return temp_rule

sqlinjection = open_json("sqlinjection")
synfloodattack = open_json("synfloodattack")
pingattack = open_json("pingattack")

sqlinjection_sid = open_json("sqlinjection_sid")
synfloodattack_sid = open_json("synfloodattack_sid")
pingattack_sid = open_json("pingattack_sid")

temp_rule = sqlinjection+synfloodattack+pingattack

def get_rules(final, temp_rule=temp_rule, save = True, sqlinjection=sqlinjection, synfloodattack=synfloodattack,
             pingattack=pingattack):
    # final_rule_sqlinjection = list()
    # final_rule_synfloodattack = list()
    # final_rule_pingattack = list()
    
    selected_rule_sqlinjection = list()
    selected_rule_synfloodattack = list()
    selected_rule_pingattack = list()
    
    for i in final:
        i= i.split()
        proto = i[0]
        source_ip = i[1]
        dest_ip = i[2]
        dest_port = i[3]
        msg = convert_msg(proto, int(dest_port))
#         print(msg)
        flag_dstnya = 'flags:S; thre$; threshold: type threshold, track by_dsc, count 1, second 60'
        rule_ = str('alert {} {} any -> {} {} any (msg: "{}"; {}; rev: 1;'.format(proto, source_ip, dest_ip, dest_port, msg, flag_dstnya))
        
        if rule_ not in temp_rule:
            if msg == "sql injection":
                selected_rule_sqlinjection.append(rule_)
#                 selected_rule.append(rule_)
            elif msg == "syn flood attack":
                selected_rule_synfloodattack.append(rule_)
            elif msg == "ping attack":
#                 print(rule_)
                selected_rule_pingattack.append(rule_)

    # print(len(selected_rule))
    sqlinjection_sid_list = get_sid(sqlinjection_sid, selected_rule_sqlinjection)
    sqlinjection = sqlinjection + selected_rule_sqlinjection
    
    synfloodattack_sid_list = get_sid(synfloodattack_sid, selected_rule_synfloodattack)
    synfloodattack = synfloodattack + selected_rule_synfloodattack
    
    pingattack_sid_list = get_sid(synfloodattack_sid, selected_rule_synfloodattack)
    pingattack = pingattack + selected_rule_pingattack
    
    if save == True:
        save_json(sqlinjection_sid_list, "sqlinjection_sid")
        save_json(sqlinjection, "sqlinjection")
        save_json(synfloodattack_sid_list, "synfloodattack_sid")
        save_json(synfloodattack, "synfloodattack")
        save_json(pingattack_sid_list, "pingattack_sid")
        save_json(pingattack, "pingattack")
        
    dict_rule = {
        'sqlinjection':make_rule(sqlinjection, sqlinjection_sid_list),
        'synfloodattack':make_rule(synfloodattack, synfloodattack_sid_list),
        'pingattack':make_rule(pingattack, pingattack_sid_list)  
    }
    return dict_rule

def save_rules(rules_list, nama_file, alamat = r"/etc/snort/rules/rules_custom"):
    if len(rules_list)>0:
        try:            
            f_out=open(alamat,"w") #ubah a
        except:
            f_out=open(nama_file+".rules","w")

        for rule in rules_list:
            f_out.write(rule)
        f_out.close()
    else:
        pass
        
def convert_msg(protocol, port):
    if protocol == 'tcp' and port == 80:
        return "sql injection"
    elif protocol == 'tcp':
        return "syn flood attack"
    elif protocol == "icmp":
        return "ping attack"
    else:
        return "<possible attack>"
    
# sqlinjection = open_json(sqlinjection)
# synfloodattack = open_json(synfloodattack)
# pingattack = open_json(pingattack)

# sqlinjection_sid = open_json(sqlinjection_sid)
# synfloodattack_sid = open_json(synfloodattack_sid)
# pingattack_sid = open_json(pingattack_sid)