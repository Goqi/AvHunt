/*
0 error(s),0 warning(s)
Team:0e0w Security Team
Author:0e0wTeam[at]gmail.com
Datetime:2022/12/24 8:57
*/

package cmd

import (
	"fmt"
	"github.com/Gogods/cobra"
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall antivirus software",
	Long:  `avRecon uninstall`,
	Run:   uninstallCommand,
}

func uninstallCommand(cmd *cobra.Command, args []string) {
	fmt.Printf("待更新发布！\n")
}
