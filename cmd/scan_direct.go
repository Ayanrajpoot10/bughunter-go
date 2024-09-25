package cmd

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Ayanrajpoot10/bughunter-go/pkg/queuescanner"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// scanDirectCmd represents the scanDirect command
var scanDirectCmd = &cobra.Command{
	Use:   "direct",
	Short: "Scan using direct connection",
	Run:   scanDirectRun,
}

var (
	scanDirectFlagFilename   string
	scanDirectFlagServerList string
	scanDirectFlagHttps      bool
	scanDirectFlagTimeout    int
	scanDirectFlagOutput     string
)

func init() {
	scanCmd.AddCommand(scanDirectCmd)

	scanDirectCmd.Flags().StringVarP(&scanDirectFlagFilename, "filename", "f", "", "domain list filename")
	scanDirectCmd.Flags().StringVarP(&scanDirectFlagServerList, "server-list", "s", "all", "server list")
	scanDirectCmd.Flags().BoolVar(&scanDirectFlagHttps, "https", false, "use https")
	scanDirectCmd.Flags().IntVar(&scanDirectFlagTimeout, "timeout", 3, "connect timeout")
	scanDirectCmd.Flags().StringVarP(&scanDirectFlagOutput, "output", "o", "", "output result")

	scanDirectCmd.MarkFlagFilename("filename")
	scanDirectCmd.MarkFlagRequired("filename")
}

type scanDirectRequest struct {
	Domain     string
	Https      bool
	ServerList []string
}

type scanDirectResponse struct {
	Color      *color.Color
	Request    *scanDirectRequest
	NetIPList  []net.IP
	StatusCode int
	Server     string
	Location   string
}

var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	},
	Timeout: 10 * time.Second,
}

var ctxBackground = context.Background()

func scanDirect(c *queuescanner.Ctx, p *queuescanner.QueueScannerScanParams) {
	req := p.Data.(*scanDirectRequest)

	ctxTimeout, cancel := context.WithTimeout(ctxBackground, 3*time.Second)
	defer cancel()
	netIPList, err := net.DefaultResolver.LookupIP(ctxTimeout, "ip4", req.Domain)
	if err != nil {
		return
	}
	ip := netIPList[0].String()

	httpScheme := "http"
	if req.Https {
		httpScheme = "https"
	}

	httpReq, err := http.NewRequest("HEAD", fmt.Sprintf("%s://%s", httpScheme, req.Domain), nil)
	if err != nil {
		return
	}

	httpRes, err := httpClient.Do(httpReq)
	if err != nil {
		return
	}

	hServer := httpRes.Header.Get("Server")
	hServerLower := strings.ToLower(hServer)
	hCfRay := httpRes.Header.Get("CF-RAY")
	hLocation := httpRes.Header.Get("Location")

	// Skip hosts redirecting to "https://jio.com/BalanceExhaust"
	if hLocation == "https://jio.com/BalanceExhaust" {
		return
	}

	resColor := color.New()

	isHiddenCloudflare := slices.Contains(req.ServerList, "cloudflare") && hCfRay != "" && hServerLower != "cloudflare"

	// Save results for all servers, not just Cloudflare
	if slices.Contains(req.ServerList, hServerLower) || isHiddenCloudflare || len(req.ServerList) == 1 {
		if isHiddenCloudflare {
			resColor = colorG1
			hServer = fmt.Sprintf("%s (cf)", hServer)
		} else {
			switch hServerLower {
			case "cloudflare":
				resColor = colorG1
			case "akamaighost":
				resColor = colorY1
			case "cloudfront":
				resColor = colorC1
			default:
				resColor = colorW1
			}
			if len(req.ServerList) == 1 {
				resColor = colorG1
			}
		}
		res := &scanDirectResponse{
			Color:      resColor,
			Request:    req,
			NetIPList:  netIPList,
			StatusCode: httpRes.StatusCode,
			Server:     hServer,
			Location:   hLocation,
		}
		c.ScanSuccess(res, nil)
	}

	if hLocation != "" {
		hLocation = fmt.Sprintf(" -> %s", hLocation)
	}

	s := fmt.Sprintf(
		"%-15s  %-3d  %-16s    %s%s",
		ip,
		httpRes.StatusCode,
		hServer,
		req.Domain,
		hLocation,
	)

	s = resColor.Sprint(s)

	c.Log(s)

	// Write the log entry to the file in real-time
	if scanDirectFlagOutput != "" {
		file, err := os.OpenFile(scanDirectFlagOutput, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		defer file.Close()

		_, err = file.WriteString(s + "\n")
		if err != nil {
			fmt.Println(err.Error())
		}
	}
}

func scanDirectRun(cmd *cobra.Command, args []string) {
	domainList := make(map[string]bool)

	domainListFile, err := os.Open(scanDirectFlagFilename)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	defer domainListFile.Close()

	scanner := bufio.NewScanner(domainListFile)
	for scanner.Scan() {
		domain := scanner.Text()
		domainList[domain] = true
	}

	var serverList []string

	scanDirectFlagServerListLower := strings.ToLower(scanDirectFlagServerList)

	if scanDirectFlagServerListLower == "all" {
		serverList = []string{
			"cloudflare",
			"cloudfront",
			"akamaighost",
		}
	} else {
		serverList = strings.Split(scanDirectFlagServerListLower, ",")
	}

	//

	queueScanner := queuescanner.NewQueueScanner(scanFlagThreads, scanDirect)
	for domain := range domainList {
		queueScanner.Add(&queuescanner.QueueScannerScanParams{
			Name: domain,
			Data: &scanDirectRequest{
				Domain:     domain,
				Https:      scanDirectFlagHttps,
				ServerList: serverList,
			},
		})
	}
	queueScanner.Start(func(c *queuescanner.Ctx) {
		if len(c.ScanSuccessList) == 0 {
			return
		}

		c.Log("")

		mapServerList := make(map[string][]*scanDirectResponse)

		for _, data := range c.ScanSuccessList {
			res, ok := data.(*scanDirectResponse)
			if !ok {
				continue
			}

			mapServerList[res.Server] = append(mapServerList[res.Server], res)
		}

		for server, resList := range mapServerList {
			if len(resList) == 0 {
				continue
			}

			var resColor *color.Color

			for _, res := range resList {
				if resColor == nil {
					resColor = res.Color
				}
			}

			c.Log(resColor.Sprintf("\n%s\n", server))
		}
	})
}
