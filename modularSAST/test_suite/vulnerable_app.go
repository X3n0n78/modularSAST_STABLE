package main

import (
	"fmt"
	"os/exec"
)

func main() {
	userInput := "echo 'sebezhető'" // Ez jöhetne pl. egy webes kérésből

	// --- VESZÉLYES ---
	// Az 'exec.Command' egy stringet kap.
	// A shell (pl. /bin/sh) fogja értelmezni, ami injektálható.
	cmdVulnerable := exec.Command("sh", "-c", userInput)
	fmt.Println(cmdVulnerable)

	// --- BIZTONSÁGOS ---
	// Az 'exec.Command' argumentum-listát kap.
	// A 'userInput' itt csak egy sima adat, nem parancs.
	cmdSafe := exec.Command("echo", "biztonságos")
	fmt.Println(cmdSafe)

	// --- A MI KEVEDVENCÜNK (amit keresni fogunk) ---
	// Az 'exec.Command' hívás a 'os/exec' csomagból.
	// Ezt a hívást kell megtalálnunk.
	exec.Command("ls", "-la")
}
