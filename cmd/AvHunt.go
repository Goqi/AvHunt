package cmd

import (
	"AvHunt/pkg/avRecon"
	"AvHunt/pkg/resources"
	"AvHunt/pkg/scanners"
	"context"
	"fmt"
	"os"

	"github.com/Gogods/cobra"
)

var (
	drivers      bool
	processes    bool
	services     bool
	registry     bool
	all          bool
	versionStr   = "1.0"
	versionCheck bool
)

func AvHunt() {
	fmt.Println("作者：0e0w | 版本：", versionStr, "\n网址：https://github.com/Goqi/AvHunt\n说明：一款简单好用的杀毒软件识别程序，暂时支持39个杀软的识别！\n")
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func scanEDRCommand(cmd *cobra.Command, args []string) {
	//fmt.Println("[AV]")
	systemData, _ := avRecon.GetSystemData(context.Background())

	for _, scanner := range scanners.Scanners {
		_, ok := scanner.Detect(systemData)
		if ok {
			fmt.Printf("发现杀软: %s\n", scanner.Name())
		}
	}
}

func edrCommand(cmd *cobra.Command, args []string) {
	if avRecon.CheckIfAdmin() {
		fmt.Println("目前在管理员权限模式下运行.\nAvHunt.exe -h 查看帮助文档.")
	} else {
		fmt.Println("目前在普通用户模式下运行，用管理员权限运行可以获得更多详细信息.\nAvHunt.exe -h 查看帮助文档.")
	}

	if all {
		processes = true
		drivers = true
		services = true
		registry = true
		fmt.Println("Scanning processes, services, drivers, and registry...")
	}

	if processes {
		fmt.Println("[PROCESSES]")
		summary, _ := avRecon.CheckProcesses()
		printProcess(summary)
		fmt.Println()
	}
	if drivers {
		fmt.Println("[DRIVERS]")
		summary, _ := avRecon.CheckDrivers()
		printDrivers(summary)
		fmt.Println()
	}
	if services {
		fmt.Println("[SERVICES]")
		summary, _ := avRecon.CheckServices()
		printServices(summary)
		fmt.Println()
	}
	if registry {
		fmt.Println("[REGISTRY]")
		summary, _ := avRecon.CheckRegistry(context.Background())
		printRegistry(summary)
		fmt.Println()
	}
}

func printProcess(summary []resources.ProcessMetaData) {
	for _, process := range summary {
		fmt.Printf("Suspicious Process Name: %s\n", process.ProcessName)
		fmt.Printf("Description: %s\n", process.ProcessDescription)
		fmt.Printf("Caption: %s\n", process.ProcessCaption)
		fmt.Printf("Binary: %s\n", process.ProcessPath)
		fmt.Printf("ProcessID: %s\n", process.ProcessPID)
		fmt.Printf("Parent Process: %s\n", process.ProcessParentPID)
		fmt.Printf("Process CmdLine: %s\n", process.ProcessCmdLine)
		fmt.Printf("File Metadata: \t%s\n", avRecon.FileMetaDataParser(process.ProcessExeMetaData))
		fmt.Printf("Matched Keyword: %s\n", process.ScanMatch)
		fmt.Println()
	}
}

func printServices(summary []resources.ServiceMetaData) {
	for _, service := range summary {
		fmt.Printf("Suspicious Service Name: %s\n", service.ServiceName)
		fmt.Printf("Display Name: %s\n", service.ServiceDisplayName)
		fmt.Printf("Caption: %s\n", service.ServiceCaption)
		fmt.Printf("CommandLine: %s\n", service.ServicePathName)
		fmt.Printf("Status: %s\n", service.ServiceState)
		fmt.Printf("ProcessID: %s\n", service.ServiceProcessId)
		fmt.Printf("File Metadata: \t%s\n", avRecon.FileMetaDataParser(service.ServiceExeMetaData))
		fmt.Printf("Matched Keyword: %s\n", service.ScanMatch)
		fmt.Println()
	}
}

func printRegistry(summary resources.RegistryMetaData) {
	fmt.Println("Scanning registry: ")
	for _, match := range summary.ScanMatch {
		fmt.Printf("\t%s\n", match)
	}
	fmt.Println()
}

func printDrivers(summary []resources.DriverMetaData) {
	for _, driver := range summary {
		fmt.Printf("Suspicious Driver Module: %s\n", driver.DriverBaseName)
		fmt.Printf("Driver FilePath: %s\n", driver.DriverFilePath)
		fmt.Printf("Driver File Metadata: \t%s\n", avRecon.FileMetaDataParser(driver.DriverSysMetaData))
		fmt.Printf("Matched Keyword: %s\n", driver.ScanMatch)
		fmt.Println()
	}
}
