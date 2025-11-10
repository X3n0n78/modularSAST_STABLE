#include <clang-c/Index.h>
#include <iostream>
#include <string>

/**
 * Kiírja a csomópont típusát és a szövegét.
 */
std::string getCursorInfo(CXCursor cursor) {
    CXString kindSpelling = clang_getCursorKindSpelling(clang_getCursorKind(cursor));
    CXString spelling = clang_getCursorSpelling(cursor);

    std::string result = "[";
    result += clang_getCString(kindSpelling);
    result += "] '";
    result += clang_getCString(spelling);
    result += "'";

    clang_disposeString(kindSpelling);
    clang_disposeString(spelling);
    return result;
}

/**
 * Rekurzív visitor, ami "behúzással" kiírja a teljes fát.
 */
CXChildVisitResult dumpVisitor(CXCursor cursor, CXCursor parent, CXClientData client_data) {
    int indentLevel = *(static_cast<int*>(client_data));
    
    // Behúzás
    for (int i = 0; i < indentLevel; ++i) {
        std::cout << "  ";
    }
    
    // Csomópont infó kiírása
    std::cout << getCursorInfo(cursor) << std::endl;

    // Rekurzió a gyerekekre
    int nextIndentLevel = indentLevel + 1;
    clang_visitChildren(cursor, dumpVisitor, &nextIndentLevel);
    
    return CXChildVisit_Continue;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Használat: ./ast_dumper <fájl>" << std::endl;
        return 1;
    }

    const char* sourceFile = argv[1];
    
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
        std::cerr << "Hiba: A C++ fájl elemzése (parse) sikertelen." << std::endl;
        return 1;
    }

    CXCursor rootCursor = clang_getTranslationUnitCursor(tu);
    
    int initialIndent = 0;
    std::cout << "--- AST DUMP KEZDETE ---" << std::endl;
    clang_visitChildren(rootCursor, dumpVisitor, &initialIndent);
    std::cout << "--- AST DUMP VÉGE ---" << std::endl;

    clang_disposeIndex(index);
    clang_disposeTranslationUnit(tu);

    return 0;
}