#include <clang-c/Index.h> // A libclang fő headerje
#include <iostream>
#include <string>
#include <set>    // Gyors kereséshez
#include <vector> // Argumentumok tárolásához
#include <fstream> // <-- ÚJ: Fájl olvasásához (a snippet-hez)
#include <sstream> 
#include <algorithm> // Ez kell a std::find_if_not-hoz
#include <cctype>    // Ez kell a ::isspace-hez// <-- ÚJ: String trimmeléshez

// Globális halmaz a veszélyes függvényneveknek
std::set<std::string> dangerousFunctions;

// Globális zászló a helyes JSON formázáshoz
static bool firstFinding = true;

/**
 * Helper: Beolvas egy adott sort egy fájlból
 */
std::string getLineFromFile(const std::string& filename, unsigned int lineNum) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return "[Hiba: fájl nem olvasható]";
    }

    std::string lineContent;
    for (unsigned int i = 1; i <= lineNum; ++i) {
        if (!std::getline(file, lineContent)) {
            return "[Hiba: sor nem található]";
        }
    }
    
    // "Whitespace" trimmelése az elejéről és végéről
    lineContent.erase(lineContent.begin(), std::find_if_not(lineContent.begin(), lineContent.end(), ::isspace));
    lineContent.erase(std::find_if_not(lineContent.rbegin(), lineContent.rend(), ::isspace).base(), lineContent.end());

    return lineContent;
}

/**
 * Egyszerű JSON "escape" függvény.
 */
std::string escapeJsonString(const std::string& input) {
    std::string output = "";
    for (char c : input) {
        switch (c) {
            case '\"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:   output += c; break;
        }
    }
    return output;
}

/**
 * Helper függvény a találat JSON-ba írásához.
 * FRISSÍTVE: Most már beolvassa a "snippet"-et is.
 */
void writeFinding(CXCursor cursor, const std::string& functionName) {
    if (!firstFinding) {
        std::cout << "," << std::endl;
    }
    firstFinding = false;

    CXSourceLocation location = clang_getCursorLocation(cursor);
    CXString cxFilename;
    unsigned int line, column;
    clang_getPresumedLocation(location, &cxFilename, &line, &column);
    
    std::string filename = clang_getCString(cxFilename);
    clang_disposeString(cxFilename);

    // --- SNIPPET BEOLVASÁSA ---
    std::string snippet = getLineFromFile(filename, line);

    // JSON kiírás
    std::cout << "  {" << std::endl;
    std::cout << "    \"file\": \"" << escapeJsonString(filename) << "\"," << std::endl;
    std::cout << "    \"line\": " << line << "," << std::endl;
    std::cout << "    \"finding\": \"" << escapeJsonString(functionName) << "\"," << std::endl;
    std::cout << "    \"snippet\": \"" << escapeJsonString(snippet) << "\"" << std::endl; // <-- ITT AZ ÚJ SOR
    std::cout << "  }";
}

/**
 * Ez a "visitor" (látogató) függvény, TISZTA LAP VERZIÓ.
 * Figyeli a 'CallExpr'-t (strcpy) ÉS az 'OverloadedDeclRef'-et (gets).
 */
CXChildVisitResult visitNode(CXCursor cursor, CXCursor parent, CXClientData client_data) {
    std::string functionName = "";
    CXCursorKind kind = clang_getCursorKind(cursor);
    CXCursor targetCursor = cursor;

    if (kind == CXCursor_CallExpr) {
        CXCursor functionCursor = clang_getCursorReferenced(cursor);
        if (!clang_isInvalid(clang_getCursorKind(functionCursor))) {
            CXString spelling = clang_getCursorSpelling(functionCursor);
            functionName = clang_getCString(spelling);
            clang_disposeString(spelling);
        } else {
             CXString spelling = clang_getCursorSpelling(cursor);
             functionName = clang_getCString(spelling);
             clang_disposeString(spelling);
        }
    }
    else if (kind == CXCursor_OverloadedDeclRef) {
        CXString spelling = clang_getCursorSpelling(cursor);
        functionName = clang_getCString(spelling);
        clang_disposeString(spelling);
        
        CXCursor p1 = clang_getCursorSemanticParent(cursor);
        CXCursor p2 = clang_getCursorSemanticParent(p1);
        if (clang_getCursorKind(p2) == CXCursor_UnexposedExpr) {
            targetCursor = p2;
        }
    }

    if (!functionName.empty() && dangerousFunctions.count(functionName)) {
        writeFinding(targetCursor, functionName);
    }
    
    return CXChildVisit_Recurse;
}


int main(int argc, char* argv[]) {
    // (A main függvény többi része változatlan maradt)
    
    if (argc < 3) {
        std::cerr << "{\"error\": \"Hiányzó argumentumok. Használat: ./cpp_analyzer <fájl> <szabály1> [szabály2]...\"}" << std::endl;
        return 1;
    }

    const char* sourceFile = argv[1];
    
    for (int i = 2; i < argc; ++i) {
        dangerousFunctions.insert(argv[i]);
    }

    CXIndex index = clang_createIndex(0, 0);
    
    const char* clang_args[] = { "-I/usr/include" };
    int num_clang_args = 1;

    CXTranslationUnit tu = clang_parseTranslationUnit(
        index,
        sourceFile, 
        clang_args, num_clang_args, 
        nullptr, 0,
        CXTranslationUnit_None
    );

    if (tu == nullptr) {
        std::cerr << "{\"error\": \"A C++ fájl elemzése (parse) sikertelen.\", \"file\": \"" << sourceFile << "\"}" << std::endl;
        clang_disposeIndex(index);
        return 1;
    }

    CXCursor rootCursor = clang_getTranslationUnitCursor(tu);
    std::cout << "[" << std::endl;
    clang_visitChildren(rootCursor, visitNode, nullptr);
    std::cout << std::endl << "]" << std::endl; 
    clang_disposeIndex(index);
    clang_disposeTranslationUnit(tu);

    return 0;
}