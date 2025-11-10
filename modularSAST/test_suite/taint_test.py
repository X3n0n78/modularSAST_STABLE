import os

def get_user_input():
    # Ez szimulál egy "szennyezett" FORRÁST
    return "valami_amit_a_tamado_irt"

# --- A TISZTA ESET ---
safe_data = "2 + 2" # Ez egy fix string, "tiszta"
eval(safe_data)     # Ezt a NYELŐT NEM SZABADNA megtalálni!

# --- A VESZÉLYES ESET ---
tainted_data = get_user_input() # <-- FORRÁS
b = tainted_data                # <-- ÁRAMLÁS (propagáció)
eval(b)                         # <-- NYELŐ (Ezt KELL megtalálni!)

# --- EGY MÁSIK VESZÉLYES ESET ---
c = get_user_input() # <-- FORRÁS
os.system(c)         # <-- NYELŐ (Ezt is meg KELL találni!)