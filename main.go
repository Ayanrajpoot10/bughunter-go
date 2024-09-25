package main

import (
    "github.com/Ayanrajpoot10/bugscanner-go/cmd"
    "github.com/fatih/color"
)

func main() {
    welcomeColor := color.New(color.FgGreen, color.Bold)

    welcomeColor.Println("Welcome to Bughunter-Go! Modified version of bugscanner-go with fixes. By:- Ayan Rajpoot ,join telegram bugScanX..")

    cmd.Execute()
}
