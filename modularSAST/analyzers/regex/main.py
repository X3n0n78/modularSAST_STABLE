import ast
import sys
import json
import os
import yaml 
import re 

# Formátum: (szabály_neve, lefordított_regex_objektum)
COMPILED_RULES = []

def load_rules(rule_filepath):
    """Betölti a 'rules' listát és lefordítja a regex mintákat."""
    global COMPILED_RULES
    try:
        with open(rule_filepath, 'r', encoding='utf-8') as f:
            rules_data = yaml.safe_load(f)
            
            rules_list = rules_data.get('rules', []) 
            if not rules_list:
                return False, "A YAML-nak tartalmaznia kell 'rules' listát."

            for rule in rules_list:
                pattern = rule.get('pattern')
                name = rule.get('name') # <-- Kinyerjük a nevet
                if pattern and name:
                    compiled_regex = re.compile(pattern)
                    # A 'name'-et tároljuk el, erre van szüksége a Go motornak
                    COMPILED_RULES.append((name, compiled_regex))
            
            return True, ""
            
    except Exception as e:
        return False, f"Hiba a szabályfájl olvasása közben: {e}"


def analyze_file_regex(filepath):
    """Végigmegy egy fájl sorain, és lefuttatja az összes regexet."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_number, line_content in enumerate(f, 1):
                
                for rule_name, compiled_regex in COMPILED_RULES:
                    if compiled_regex.search(line_content):
                        findings.append({
                            "file": filepath,
                            "line": line_number,
                            "finding": rule_name, # <-- JAVÍTÁS: A 'name'-et küldjük
                            "snippet": line_content.strip()
                        })
                        break 
                        
    except Exception as e:
        return [{"file": filepath, "finding": "REGEX ELEMZŐ HIBA", "message": f"Fájl olvasási hiba: {e}"}]
    
    return findings


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(json.dumps([{"error": "Hiányzó argumentumok. Használat: python3 main.py <szabályfájl> <vizsgálandó_fájl>"}]))
        sys.exit(1)
        
    rule_filepath = sys.argv[1]
    file_to_scan = sys.argv[2]
    
    success, error_msg = load_rules(rule_filepath)
    if not success:
        print(json.dumps([{"error": error_msg}]))
        sys.exit(1)
    
    results = analyze_file_regex(file_to_scan)
    
    print(json.dumps(results, indent=2, ensure_ascii=False))