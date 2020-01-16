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

    final = np.array(data_str)[index_final]
    return final


with open('old_rules_.json', 'r') as f:
    temp_rule = json.load(f)
# temp_rule = list()

with open('sid.json', 'r') as f:
    temp_sid = json.load(f)
    
# temp_sid = [10000]

def get_rules(final, temp_rule=temp_rule, save = True):
    final_rule = list()
    selected_rule = list()
    for i in final:
        i= i.split()
        proto = i[0]
        source_ip = i[1]
        dest_ip = i[2]
        dest_port = i[3]
#         print(type(dest_port))
        msg = convert_msg(proto, int(dest_port))
        flag_dstnya = 'flags:S; thre$; threshold: type threshold, track by_dsc, count 1, second 60'
    #     temp_sid.append(sid)
        rule_ = str('alert {} {} any -> {} {} any msg: "{}"; {}; rev: 1;'.format(proto, source_ip, dest_ip, dest_port, msg, flag_dstnya))
    #     print(rule_)
        if rule_ not in temp_rule:
            selected_rule.append(rule_)

    # print(len(selected_rule))
    sid_list =[x for x in range(temp_sid[-1], temp_sid[-1]+len(selected_rule))]
    temp_rule = temp_rule+selected_rule
    sid_list = temp_sid+sid_list
    
    if save == True:
        with open('sid.json', 'w') as f:
            json.dump(sid_list, f)
        with open('old_rules_.json', 'w') as f:
            json.dump(temp_rule, f)
#     print(sid_list)
    for i in range(len(temp_rule)):
        sid = sid_list[i]
        rule_sid = temp_rule[i]+" sid:"+str(sid)+";\n"
        final_rule.append(rule_sid)
    return final_rule

def save_rules(rules_list, alamat = r"/etc/snort/rules/local.rules"):
    try:            
        f_out=open(alamat,"w") #ubah a
    except:
        f_out=open("local.rules","w")
        
    for rule in rules_list:
        f_out.write(rule)
    print("succes!")
    f_out.close()

def convert_msg(protocol, port):
    if protocol == 'tcp' and port == 80:
        return "sql injection"
    elif protocol == 'tcp':
        return "syn flood attack"
    elif protocol == "icmp":
        return "ping attack"
    else:
        return "<possible attack>"
    
