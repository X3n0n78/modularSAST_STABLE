import ast
import sys
import json
import os
import yaml
import re

# --- A Taint Analízis "Agya" ---

TAINT_SOURCES = set()
TAINT_SINKS = set() # Ez lesz a "nyelők" (sinks) listája
SANITIZERS = set() # Sanitizer függvények

# Known sanitizers that clean tainted data
DEFAULT_SANITIZERS = {
    'html.escape', 'html.unescape',
    're.escape',
    'urllib.parse.quote', 'urllib.parse.quote_plus',
    'bleach.clean', 'bleach.linkify',
    'markupsafe.escape',
    'werkzeug.security.escape',
    'jinja2.escape',
    'str.replace', 'str.strip', 'str.removeprefix', 'str.removesuffix',
    'os.path.basename', 'os.path.normpath', 'os.path.abspath',
    'pathlib.Path',
    'int', 'float', 'str', 'bool'  # Type conversions can sanitize
}

def load_rules(rule_filepath):
    """
    Betölti a 'sources' és 'rules' (ami a 'sinks'-et helyettesíti) listákat.
    """
    global TAINT_SOURCES, TAINT_SINKS, SANITIZERS
    try:
        with open(rule_filepath, 'r', encoding='utf-8') as f:
            rules = yaml.safe_load(f)

            sources = rules.get('sources', [])
            rules_list = rules.get('rules', [])
            sanitizers = rules.get('sanitizers', [])

            if not sources or not rules_list:
                return False, "A YAML-nak tartalmaznia kell 'sources' és 'rules' listákat."

            TAINT_SOURCES = set(sources)
            SANITIZERS = DEFAULT_SANITIZERS.union(set(sanitizers))

            for rule in rules_list:
                pattern = rule.get('pattern')
                if pattern:
                    TAINT_SINKS.add(pattern) # Betöltjük az összes nyelőt/mintát

            return True, ""

    except Exception as e:
        return False, f"Hiba a szabályfájl olvasása közben: {e}"

def check_suppression(source_code, line_num, rule_pattern):
    """
    Ellenőrzi, hogy van-e suppression komment az adott sorban vagy az előző sorban.
    Formátum: # nosast: rule-name vagy # nosast
    """
    lines = source_code.split('\n')
    if line_num < 1 or line_num > len(lines):
        return False

    # Check current line and previous line
    for line_idx in [line_num - 1, line_num - 2]:
        if line_idx < 0 or line_idx >= len(lines):
            continue

        line = lines[line_idx]
        # Match # nosast or # nosast: pattern-name
        if re.search(r'#\s*nosast(?::\s*(\S+))?', line, re.IGNORECASE):
            match = re.search(r'#\s*nosast(?::\s*(\S+))?', line, re.IGNORECASE)
            if match.group(1):
                # Specific rule suppression
                if rule_pattern in match.group(1) or match.group(1) == 'all':
                    return True
            else:
                # General suppression
                return True

    return False


class TaintVisitor(ast.NodeVisitor):
    """
    HIBRID Visitor: Képes Taint (adatfolyam) és Pattern (minta)
    alapú elemzésre is. Támogatja a sanitizer detektálást és confidence score számítást.
    """
    def __init__(self, source_code):
        self.tainted_vars = set()
        self.sanitized_vars = set()  # Variables that were sanitized
        self.findings = []
        self.source_code = source_code

    def visit_Assign(self, node):
        """Meghívódik minden 'valami = ...' műveletnél."""

        # --- ÁRAMLÁS (Propagáció) ---
        if isinstance(node.value, ast.Name):
            source_var_name = node.value.id
            if source_var_name in self.tainted_vars:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # Check if it's been sanitized
                        if source_var_name not in self.sanitized_vars:
                            self.tainted_vars.add(target.id)

        # --- FORRÁS Észlelése ---
        if isinstance(node.value, ast.Call):
            call = node.value
            func_name = ""
            if isinstance(call.func, ast.Name):
                func_name = call.func.id
            elif isinstance(call.func, ast.Attribute):
                try: func_name = ast.unparse(call.func)
                except: pass

            # Check if it's a sanitizer function
            if func_name in SANITIZERS:
                # Mark the result as sanitized
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.sanitized_vars.add(target.id)
                        # Remove from tainted vars if it was tainted
                        self.tainted_vars.discard(target.id)
            elif func_name in TAINT_SOURCES: # <-- A YAML-ból olvasva
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)

        self.generic_visit(node)

    def calculate_confidence(self, func_name, is_tainted, is_pattern_based, has_sanitizer, is_suppressed):
        """
        Calculate confidence score (0-100) based on various factors.
        """
        if is_suppressed:
            return 0  # Suppressed findings have 0 confidence

        base_confidence = 50

        # Pattern-based findings are generally high confidence
        if is_pattern_based:
            base_confidence = 85

        # Taint-based findings with actual tainted data
        if is_tainted:
            base_confidence += 30

        # Sanitizer reduces confidence significantly
        if has_sanitizer:
            base_confidence -= 40

        # Specific patterns boost confidence
        if func_name in ['eval', 'exec', 'pickle.load', 'yaml.load']:
            base_confidence += 15

        # Clamp to 0-100 range
        return max(0, min(100, base_confidence))

    def visit_Call(self, node):
        """
        Meghívódik minden 'valami(...)' hívásnál.
        Most már kétféle logikát futtat, confidence score-ral és suppression ellenőrzéssel.
        """
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            try: func_name = ast.unparse(node.func)
            except: pass

        # Ellenőrizzük, hogy ez a függvény érdekel-e minket egyáltalán
        if func_name in TAINT_SINKS:
            # Check suppression
            is_suppressed = check_suppression(self.source_code, node.lineno, func_name)

            # --- LOGIKA 1: Minta-alapú elemzés (pl. subprocess) ---
            if func_name.startswith("subprocess."):
                is_shell_true = False
                for kw in node.keywords:
                    if kw.arg == 'shell':
                        if (isinstance(kw.value, ast.Constant) and kw.value.value is True) or \
                           (hasattr(ast, 'NameConstant') and isinstance(kw.value, ast.NameConstant) and kw.value.value is True):
                            is_shell_true = True
                            break

                if is_shell_true:
                    confidence = self.calculate_confidence(func_name, False, True, False, is_suppressed)
                    if confidence > 0:  # Don't add suppressed findings
                        self.findings.append({
                            "file": current_file,
                            "line": node.lineno,
                            "finding": func_name,
                            "snippet": ast.unparse(node).strip(),
                            "confidence": confidence
                        })

            # --- LOGIKA 2: Taint-alapú elemzés (pl. eval, os.system) ---
            else:
                is_tainted_call = False
                has_sanitizer_in_chain = False

                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        if arg.id in self.tainted_vars:
                            is_tainted_call = True
                            # Check if the variable was sanitized
                            if arg.id in self.sanitized_vars:
                                has_sanitizer_in_chain = True
                        break

                    # Check for inline sanitizer calls
                    if isinstance(arg, ast.Call):
                        arg_func_name = ""
                        if isinstance(arg.func, ast.Name):
                            arg_func_name = arg.func.id
                        elif isinstance(arg.func, ast.Attribute):
                            try: arg_func_name = ast.unparse(arg.func)
                            except: pass

                        if arg_func_name in SANITIZERS:
                            has_sanitizer_in_chain = True

                if is_tainted_call:
                    confidence = self.calculate_confidence(func_name, True, False, has_sanitizer_in_chain, is_suppressed)
                    if confidence > 0:  # Don't add suppressed findings
                        self.findings.append({
                            "file": current_file,
                            "line": node.lineno,
                            "finding": func_name,
                            "snippet": ast.unparse(node).strip(),
                            "confidence": confidence
                        })

        self.generic_visit(node)

# Globális a fájlnév tárolásához
current_file = ""

def analyze_taint(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            tree = ast.parse(content, filename=filepath)

            visitor = TaintVisitor(content)
            visitor.visit(tree)
            return visitor.findings

    except Exception as e:
        return [{"file": filepath, "finding": "PYTHON ELEMZŐ HIBA", "message": f"Taint elemzési hiba: {e}"}]

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(json.dumps([{"error": "Hiányzó argumentumok. Használat: python3 main.py <szabályfájl> <vizsgálandó_fájl>"}]))
        sys.exit(1)
        
    rule_filepath = sys.argv[1]
    current_file = sys.argv[2]
    
    # 1. Szabályok betöltése
    success, error_msg = load_rules(rule_filepath)
    if not success:
        print(json.dumps([{"error": error_msg}]))
        sys.exit(1)
    
    # 2. Elemzés futtatása
    results = analyze_taint(current_file)
    
    print(json.dumps(results, indent=2, ensure_ascii=False))