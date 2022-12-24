/*
0 error(s),0 warning(s)
Team:0e0w Security Team
Author:0e0wTeam[at]gmail.com
Datetime:2022/12/24 8:51
*/

package cmd

import (
	"github.com/Gogods/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "scan installed antivirus",
	Long:  `scan edrs`,
	Run:   scanEDRCommand,
}
