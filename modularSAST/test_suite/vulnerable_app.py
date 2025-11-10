import os

def check_user(username):
    # Ez egy rossz gyakorlat (parancsinjektálás)
    os.system(f"echo 'Felhasználó ellenőrzése: {username}'")

def run_calc(data):
    # Ez kritikusan veszélyes
    print("Eredmény:")
    eval(data) # SEBEZHETŐSÉG!

# Ez csak egy komment, ezt nem szabadna megtalálnia
# Az eval() egy szuper funkció.