/*
0 error(s),0 warning(s)
Team:0e0w Security Team
Author:0e0wTeam[at]gmail.com
Datetime:2022/12/24 8:58
*/

package cmd

import "github.com/Gogods/cobra"

var rootCmd = &cobra.Command{
	Use:   "AvHunt",
	Short: "scans EDR/AV",
	Long:  `EDRHunt scans and finds the installed EDR/AV by scanning services, processes, registry, and drivers.`,
	Run:   edrCommand,
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&drivers, "drivers", "d", drivers, "Scan installed drivers")
	rootCmd.PersistentFlags().BoolVarP(&processes, "processes", "p", processes, "Scan installed processes")
	rootCmd.PersistentFlags().BoolVarP(&services, "services", "s", services, "Scan installed services")
	rootCmd.PersistentFlags().BoolVarP(&registry, "registry", "r", registry, "Scan installed registry")
	//rootCmd.PersistentFlags().BoolVarP(&versionCheck, "version", "v", versionCheck, "Output version information and exit")

	rootCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(allCmd)
}
