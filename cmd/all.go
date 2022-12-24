/*
0 error(s),0 warning(s)
Team:0e0w Security Team
Author:0e0wTeam[at]gmail.com
Datetime:2022/12/24 8:49
*/

package cmd

import "github.com/Gogods/cobra"

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "scan installed antivirus",
	Long:  `scan edrs and show system data`,
	Run:   allCommand,
}

func allCommand(cmd *cobra.Command, args []string) {
	all = true
	edrCommand(cmd, args)
	scanEDRCommand(cmd, args)
}
