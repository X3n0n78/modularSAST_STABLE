#include <stdio.h>  // gets-hez és sprintf-hez
#include <string.h> // strcpy-hez

int main() {
    char name[50];
    char constant_string[] = "Ez egy konstans string, ami hosszabb mint 20 byte";
    char buffer[20];
    char sprintf_buffer[100]; // Egy másik buffer

    printf("Kérem, adja meg a nevét: ");
    
    // KRITIKUS hiba: gets()
    gets(name); 

    printf("Üdv, %s!\n", name);

    // MAGAS kockázatú hiba: strcpy()
    strcpy(buffer, constant_string);

    // ÚJ MAGAS kockázatú hiba: sprintf()
    // A 'name' hosszabb is lehet, mint a 'sprintf_buffer' maradék helye
    sprintf(sprintf_buffer, "A felhasználó neve: %s", name);

    // ... a 'sprintf' hívás után ...

    // ÚJ MAGAS kockázatú hiba: strcat()
    // A 'name' (ami 50 byte) és a 'sprintf_buffer' (ami 100 byte)
    // együtt már túlcsordulhatnak.
    strcat(sprintf_buffer, name);

    return 0;
}

    return 0;
}