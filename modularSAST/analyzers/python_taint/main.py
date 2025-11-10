import ast
import sys
import json
import os

# --- A Taint Analízis "Agya" ---

# 1. Definiáljuk a szabályokat (egyelőre fixen)
TAINT_SOURCES = {'get_user_input'} # Függvények, amik "szennyeznek"
TAINT_SINKS = {'eval', 'os.system'}  # Függvények, amik "nyelők"

class TaintVisitor(ast.NodeVisitor):
    """
    Ez a Visitor végigjárja a fát, és ÁLLAPOTOT tart nyilván
    arról, hogy mely változók "szennyezettek".
    """
    def __init__(self):
        # Ebben a 'set'-ben tároljuk az összes változónevet,
        # ami "szennyezett" adatot hordoz.
        self.tainted_vars = set()
        self.findings = []

    def visit_Assign(self, node):
        """Meghívódik minden 'valami = ...' műveletnél."""
        
        # --- 2. ÁRAMLÁS (Propagáció) ---
        # Pl. 'b = tainted_data'
        if isinstance(node.value, ast.Name):
            source_var_name = node.value.id
            if source_var_name in self.tainted_vars:
                # Ha a jobb oldal (forrás) szennyezett,
                # szennyezzük a bal oldalt (cél) is.
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)

        # --- 1. FORRÁS Észlelése ---
        # Pl. 'tainted_data = get_user_input()'
        if isinstance(node.value, ast.Call):
            call = node.value
            # Megnézzük a hívott függvény nevét
            func_name = ""
            if isinstance(call.func, ast.Name):
                func_name = call.func.id
            
            if func_name in TAINT_SOURCES:
                # Ez egy FORRÁS! Minden változót, aminek
                # ezt az értéket adjuk, "szennyezetté" teszünk.
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)

        # Folytatjuk a bejárást, hátha pl. 'a = b = get_user_input()'
        self.generic_visit(node)

    def visit_Call(self, node):
        """Meghívódik minden 'valami(...)' hívásnál."""

        # --- 3. NYELŐ Észlelése ---
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute): # pl. os.system
            try:
                func_name = ast.unparse(node.func)
            except:
                pass # Nem érdekel, ha nem tudjuk kiolvasni

        if func_name in TAINT_SINKS:
            # Ez egy NYELŐ! Ellenőrizzük az argumentumait.
            is_tainted_call = False
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    arg_name = arg.id
                    if arg_name in self.tainted_vars:
                        # --- 4. RIASZTÁS! ---
                        is_tainted_call = True
                        break
            
            if is_tainted_call:
                # --- ITT VOLT A HIBA ---
                # Javítva: 'ast.get_lineno(node)' helyett 'node.lineno'
                pos = node.lineno 
                # --- JAVÍTÁS VÉGE ---
                
                self.findings.append({
                    "file": current_file, # (Ezt a 'main' adja majd át)
                    "line": pos,
                    "finding": f"Taint Analysis: Szennyezett adat jutott el ide: {func_name}()",
                    "snippet": ast.unparse(node).strip()
                })
        
        self.generic_visit(node)

# Globális, mert a Visitor nem fér hozzá a 'main' argumentumaihoz
current_file = ""

def analyze_taint(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            tree = ast.parse(content, filename=filepath)
            
            visitor = TaintVisitor()
            visitor.visit(tree)
            return visitor.findings
            
    except Exception as e:
        return [{"file": filepath, "error": f"Taint elemzési hiba: {e}"}]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps([{"error": "Nincs megadva fájlnév."}]))
        sys.exit(1)
        
    current_file = sys.argv[1] # Beállítjuk a globális változót
    
    results = analyze_taint(current_file)
    
    print(json.dumps(results, indent=2, ensure_ascii=False))