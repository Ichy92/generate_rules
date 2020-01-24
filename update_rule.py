import pandas as pd

import lib
alamat = r"/etc/snort/rules/rules_custom"
df = pd.read_csv("databaru.csv", sep=";")
final = lib.find_used(df, batas_min = 10)
rules = lib.get_rules(final, save = True)
print('pingattack', rules['pingattack'])
print('sqlinjection', rules['sqlinjection'])
print('synfloodattack', rules['synfloodattack'])

try:
    lib.save_rules(rules['sqlinjection'], "sqlinjection", alamat)
    print('sql injection!')
    lib.save_rules(rules['synfloodattack'], "synfloodattack", alamat)
    print('syn flood attack!')
    lib.save_rules(rules['pingattack'], "ping", alamat)
    print('ping attack!')
    print("*"*100)
    print('success!')
    #ds
except:
    pass