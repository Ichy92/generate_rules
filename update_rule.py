import pandas as pd

import lib
alamat = r"/etc/snort/rules/rules_custom/"
df = pd.read_csv("databaru.csv", sep=";")
final = lib.find_used(df, batas_min = 8)
rules = lib.get_rules(final, save = True)

lib.save_rules(rules['sqlinjection'], "rsqlinjection", alamat)
print('sql injection!')
lib.save_rules(rules['synfloodattack'], "rsynfloodattack", alamat)
print('syn flood attack!')
lib.save_rules(rules['pingattack'], "rpingattack", alamat)
print('ping attack!')
print("*"*100)
print('success!')