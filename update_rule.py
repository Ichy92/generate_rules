import pandas as pd

import lib

df = pd.read_csv("databaru.csv", sep=";")
final = lib.find_used(df, batas_min = 8)
rules = lib.get_rules(final, save = True)
lib.save_rules(rules)