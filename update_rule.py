import pandas as pd

import lib

df = pd.read_csv("databaru.csv", sep=";")
final = lib.find_used(df, batas_min = 8)
rules = lib.get_rules(final, save = True)

lib.save_rules(rules['sqlinjection'], "sqlinjection")
print('sql injection!')
lib.save_rules(rules['synfloodattack'], "synfloodattack")
print('syn flood attack!')
lib.save_rules(rules['pingattack'], "pingattack")
print('ping attack!')
print("*"*100)
print('success!')