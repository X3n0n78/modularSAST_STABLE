package main

import (
	"bufio" // <-- ÚJ: Hatékony soronkénti olvasáshoz
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings" // <-- ÚJ: A 'trim' művelethez
)

// A mi egyszerűsített kimeneti struktúránk
type Finding struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Finding string `json:"finding"`
	Snippet string `json:"snippet"` // Ezt most már ki fogjuk tölteni!
}

// --- ÚJ HELPER FÜGGVÉNY: Sor beolvasása ---
func getLineFromFile(filename string, lineNum int) string {
	file, err := os.Open(filename)
	if err != nil {
		return "[Hiba: fájl nem olvasható]"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	currentLine := 1
	for scanner.Scan() {
		if currentLine == lineNum {
			// Megvan a sor, "trimmeljük" (felesleges szóközök levágása)
			return strings.TrimSpace(scanner.Text())
		}
		currentLine++
	}
	return "[Hiba: sor nem található]"
}

// ASTVisitor végigjárja a Go kódot
type ASTVisitor struct {
	FSet     *token.FileSet
	Findings []Finding
	Rules    map[string]bool // A keresendő minták (pl. "exec.Command")
}

// A 'Visit' metódus (FRISSÍTVE)
func (v *ASTVisitor) Visit(node ast.Node) ast.Visitor {
	if node == nil {
		return nil
	}

	callExpr, ok := node.(*ast.CallExpr)
	if !ok {
		return v
	}

	selector, ok := callExpr.Fun.(*ast.SelectorExpr)
	if !ok {
		return v
	}

	pkgIdent, ok := selector.X.(*ast.Ident)
	if !ok {
		return v
	}

	fullCallName := pkgIdent.Name + "." + selector.Sel.Name

	// ELLENŐRZÉS: Ez a név szerepel a szabályaink között?
	if v.Rules[fullCallName] {
		pos := v.FSet.Position(node.Pos())

		// --- ITT AZ ÚJ RÉSZ ---
		snippet := getLineFromFile(pos.Filename, pos.Line)

		v.Findings = append(v.Findings, Finding{
			File:    pos.Filename,
			Line:    pos.Line,
			Finding: fullCallName,
			Snippet: snippet, // <-- "N/A" helyett a valódi kódrészlet
		})
	}

	return v
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println(json.NewEncoder(os.Stdout).Encode([]Finding{}))
		os.Exit(0)
	}

	filePath := os.Args[1]
	rulesToFind := make(map[string]bool)
	for _, rule := range os.Args[2:] {
		rulesToFind[rule] = true
	}

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		fmt.Printf("[{\"file\": \"%s\", \"finding\": \"GO ELEMZŐ HIBA\", \"message\": \"%v\"}]", filePath, err)
		os.Exit(1)
	}

	visitor := &ASTVisitor{
		FSet:     fset,
		Findings: []Finding{},
		Rules:    rulesToFind,
	}
	ast.Walk(visitor, node)

	json.NewEncoder(os.Stdout).Encode(visitor.Findings)
}
