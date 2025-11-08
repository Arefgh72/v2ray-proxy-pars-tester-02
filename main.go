package main

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	proxyListURL       = "https://raw.githubusercontent.com/Arefgh72/vray-proxy-pars-tester/main/output/github_all.txt"

  testURL            = "https://aistudio.google.com/"
	requestTimeout     = 12 * time.Second
	xrayRepoAPI        = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
	xrayExecutable     = "xray"
	maxConcurrentTests = 100
	outputDir          = "output"
)

type HealthyProxy struct {
	Link    string
	Latency time.Duration
	Type    string
}

// (setupXray, readProxiesFromFile, and xray config parsers are unchanged)
func setupXray() (string, error) {
	if _, err := os.Stat(xrayExecutable); err == nil {
		fmt.Println("xray executable already exists.")
		return xrayExecutable, nil
	}
	fmt.Println("Downloading xray...")
	resp, err := http.Get(xrayRepoAPI)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var releaseInfo struct {
		Assets []struct {
			Name        string `json:"name"`
			DownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&releaseInfo); err != nil {
		return "", err
	}
	var downloadURL string
	for _, asset := range releaseInfo.Assets {
		if asset.Name == "Xray-linux-64.zip" {
			downloadURL = asset.DownloadURL
			break
		}
	}
	if downloadURL == "" {
		return "", fmt.Errorf("could not find Xray-linux-64.zip")
	}
	zipResp, err := http.Get(downloadURL)
	if err != nil {
		return "", err
	}
	defer zipResp.Body.Close()
	zipFile, err := ioutil.TempFile("", "xray-*.zip")
	if err != nil {
		return "", err
	}
	defer os.Remove(zipFile.Name())
	_, err = io.Copy(zipFile, zipResp.Body)
	if err != nil {
		return "", err
	}
	zipFile.Close()
	r, err := zip.OpenReader(zipFile.Name())
	if err != nil {
		return "", err
	}
	defer r.Close()
	for _, f := range r.File {
		if f.Name == xrayExecutable {
			outFile, err := os.OpenFile(xrayExecutable, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return "", err
			}
			rc, err := f.Open()
			if err != nil {
				return "", err
			}
			_, err = io.Copy(outFile, rc)
			outFile.Close()
			rc.Close()
			if err != nil {
				return "", err
			}
			fmt.Println("xray downloaded.")
			return xrayExecutable, nil
		}
	}
	return "", fmt.Errorf("xray executable not found in zip")
}

func readProxiesFromFile(filepath string) ([]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func createXrayConfig(proxyLink string, localPort int) ([]byte, string, error) {
	var outbound map[string]interface{}
	var protocol string
	var err error

	if strings.HasPrefix(proxyLink, "vmess://") {
		outbound, err = parseVmess(proxyLink)
		protocol = "vmess"
	} else {
		u, err := url.Parse(proxyLink)
		if err != nil {
			return nil, "", fmt.Errorf("could not parse proxy link: %v", err)
		}
		protocol = u.Scheme

		switch protocol {
		case "vless", "trojan":
			outbound, err = parseVlessTrojan(u)
		case "ss":
			outbound, err = parseShadowsocks(u)
		case "hysteria":
			outbound, err = parseHysteria(u)
		default:
			return nil, "", fmt.Errorf("unsupported protocol: %s", protocol)
		}
	}

	if err != nil {
		return nil, "", err // Propagate parser errors
	}

	config := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning", // Reduce noise
		},
		"inbounds": []map[string]interface{}{{
			"port":     localPort,
			"protocol": "socks",
			"settings": map[string]interface{}{"auth": "noauth"},
		}},
		"outbounds": []map[string]interface{}{outbound},
	}

	configBytes, err := json.MarshalIndent(config, "", "  ") // Use MarshalIndent for readability
	return configBytes, protocol, err
}

func parseVlessTrojan(u *url.URL) (map[string]interface{}, error) {
	port, _ := strconv.Atoi(u.Port())
	q := u.Query()

	// Base vnext structure
	vnext := map[string]interface{}{
		"address": u.Hostname(),
		"port":    port,
		"users": []map[string]interface{}{
			{"id": u.User.Username()},
		},
	}

	// Add flow for vless
	if u.Scheme == "vless" {
		vnext["users"].([]map[string]interface{})[0]["flow"] = "xtls-rprx-vision"
	}

	// Stream settings
	streamSettings := map[string]interface{}{
		"network":  q.Get("type"),
		"security": q.Get("security"),
	}

	// TLS settings
	if q.Get("security") == "tls" {
		tlsSettings := map[string]interface{}{"serverName": q.Get("sni")}
		if q.Get("alpn") != "" {
			tlsSettings["alpn"] = strings.Split(q.Get("alpn"), ",")
		}
		streamSettings["tlsSettings"] = tlsSettings
	}

	// Specific network settings
	switch q.Get("type") {
	case "ws":
		streamSettings["wsSettings"] = map[string]interface{}{
			"path": q.Get("path"),
			"headers": map[string]string{
				"Host": q.Get("host"),
			},
		}
	case "grpc":
		streamSettings["grpcSettings"] = map[string]interface{}{
			"serviceName": q.Get("serviceName"),
		}
	}

	return map[string]interface{}{
		"protocol":       u.Scheme,
		"settings":       map[string]interface{}{"vnext": []map[string]interface{}{vnext}},
		"streamSettings": streamSettings,
	}, nil
}

func parseShadowsocks(u *url.URL) (map[string]interface{}, error) {
	port, _ := strconv.Atoi(u.Port())

	// Handle two types of ss links:
	// 1. ss://method:password@server:port
	// 2. ss://base64(method:password)@server:port

	var method, password string

	userInfo := u.User.String()

	// Check if user info is Base64 encoded
	decoded, err := base64.URLEncoding.DecodeString(userInfo)
	if err == nil {
		userInfo = string(decoded)
	} else {
		// If not base64, URL decoding might have happened, so re-encode then decode to handle special chars
		 reEncoded, _ := url.QueryUnescape(userInfo)
		 decoded, err = base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(reEncoded)
		 if err == nil {
			 userInfo = string(decoded)
		 }
	}


	parts := strings.SplitN(userInfo, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid shadowsocks user info format: %s", userInfo)
	}
	method, password = parts[0], parts[1]

	return map[string]interface{}{
		"protocol": "shadowsocks",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{{
				"address":  u.Hostname(),
				"port":     port,
				"method":   method,
				"password": password,
			}},
		},
	}, nil
}

func parseVmess(proxyLink string) (map[string]interface{}, error) {
	re := regexp.MustCompile(`[^a-zA-Z0-9+/=]`)
	sanitizedLink := re.ReplaceAllString(strings.TrimPrefix(proxyLink, "vmess://"), "")

	decoded, err := base64.StdEncoding.DecodeString(sanitizedLink)
	if err != nil {
		// Try URL-safe decoding as a fallback
		decoded, err = base64.URLEncoding.DecodeString(sanitizedLink)
		if err != nil {
			return nil, fmt.Errorf("invalid vmess link (base64 decode failed): %w", err)
		}
	}

	var vmessDetails map[string]interface{}
	if err := json.Unmarshal(decoded, &vmessDetails); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vmess json: %w", err)
	}

	port, _ := strconv.Atoi(fmt.Sprintf("%v", vmessDetails["port"]))
	aid, _ := strconv.Atoi(fmt.Sprintf("%v", vmessDetails["aid"]))

	outbound := map[string]interface{}{
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{{
				"address": fmt.Sprintf("%v", vmessDetails["add"]),
				"port":    port,
				"users": []map[string]interface{}{{
					"id":       fmt.Sprintf("%v", vmessDetails["id"]),
					"alterId":  aid,
					"security": "auto", // Best practice
				}},
			}},
		},
		"streamSettings": map[string]interface{}{
			"network":  fmt.Sprintf("%v", vmessDetails["net"]),
			"security": fmt.Sprintf("%v", vmessDetails["tls"]),
		},
	}

	streamSettings := outbound["streamSettings"].(map[string]interface{})

	if vmessDetails["tls"] == "tls" {
		streamSettings["tlsSettings"] = map[string]interface{}{
			"serverName": fmt.Sprintf("%v", vmessDetails["sni"]),
		}
	}

	switch vmessDetails["net"] {
	case "ws":
		streamSettings["wsSettings"] = map[string]interface{}{
			"path": fmt.Sprintf("%v", vmessDetails["path"]),
			"headers": map[string]string{
				"Host": fmt.Sprintf("%v", vmessDetails["host"]),
			},
		}
	case "grpc":
		streamSettings["grpcSettings"] = map[string]interface{}{
			"serviceName": fmt.Sprintf("%v", vmessDetails["path"]),
		}
	}

	return outbound, nil
}

func parseHysteria(u *url.URL) (map[string]interface{}, error) {
	port, _ := strconv.Atoi(u.Port())
	return map[string]interface{}{
		"protocol": "hysteria",
		"settings": map[string]interface{}{
			"server":     fmt.Sprintf("%s:%d", u.Hostname(), port),
			"auth_str":   u.Query().Get("auth"),
			"insecure":   true,
			"up_mbps":    10,
			"down_mbps":  50,
		},
	}, nil
}

func testSingleProxy(xrayPath, proxyLink string, localPort int) (HealthyProxy, error) {
	configJSON, protocol, err := createXrayConfig(proxyLink, localPort)
	if err != nil {
		return HealthyProxy{}, fmt.Errorf("config error: %w", err)
	}

	configFile, err := ioutil.TempFile("", "xray-*.json")
	if err != nil {
		return HealthyProxy{}, err
	}
	defer os.Remove(configFile.Name())

	if _, err := configFile.Write(configJSON); err != nil {
		configFile.Close() // Close file before returning
		return HealthyProxy{}, err
	}
	configFile.Close()

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout+2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "./"+xrayPath, "-c", configFile.Name())
	// IMPORTANT: Discard stdout and stderr to prevent the process from blocking
	// when the OS buffer fills up. This is a common cause of deadlocks.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		return HealthyProxy{}, err
	}

	// Give xray a moment to initialize the local SOCKS server
	time.Sleep(500 * time.Millisecond)

	httpClient := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "socks5", Host: fmt.Sprintf("127.0.0.1:%d", localPort)})},
		Timeout:   requestTimeout,
	}

	start := time.Now()
	resp, err := httpClient.Get(testURL)
	latency := time.Since(start)

	// Ensure the process is terminated and resources are cleaned up.
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
	cmd.Wait() // Wait to release process resources.

	if err != nil {
		return HealthyProxy{}, fmt.Errorf("test failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		return HealthyProxy{}, fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	return HealthyProxy{Link: proxyLink, Latency: latency, Type: protocol}, nil
}

// TestUpdate is used to send progress updates from workers to the reporter.
type TestUpdate struct {
	IsHealthy bool
}

func testProxies(proxies []string, xrayPath string) []HealthyProxy {
	totalProxies := len(proxies)
	fmt.Printf("\n--- Starting to test %d proxies with %d concurrent workers... ---\n", totalProxies, maxConcurrentTests)

	var healthyProxies []HealthyProxy
	var workerWg sync.WaitGroup

	proxyChan := make(chan string, totalProxies)
	for _, p := range proxies {
		proxyChan <- p
	}
	close(proxyChan)

	// A channel for workers to report success or failure.
	progressChan := make(chan TestUpdate, totalProxies)
	// A separate channel to collect only the healthy proxies.
	healthyChan := make(chan HealthyProxy, totalProxies)

	// --- Dedicated Progress Reporter Goroutine ---
	// This goroutine is the ONLY one that prints to the console, preventing race conditions.
	var reporterWg sync.WaitGroup
	reporterWg.Add(1)
	go func() {
		defer reporterWg.Done()
		var testedCount, healthyCount int64
		startTime := time.Now()

		for update := range progressChan {
			testedCount++
			if update.IsHealthy {
				healthyCount++
			}

			// Calculate progress and ETA
			elapsed := time.Since(startTime).Seconds()
			speed := float64(testedCount) / elapsed
			eta := 0.0
			if speed > 0 {
				eta = float64(totalProxies-int(testedCount)) / speed
			}
			healthyPercentage := 0.0
			if testedCount > 0 {
				healthyPercentage = float64(healthyCount) * 100 / float64(testedCount)
			}

			// Print on a single line
			fmt.Printf(
				"\rTesting... [%d/%d] | Healthy: %d (%.2f%%) | Speed: %.2f p/s | ETA: %.0fs ",
				testedCount,
				totalProxies,
				healthyCount,
				healthyPercentage,
				speed,
				eta,
			)
		}
	}()

	// --- Worker Goroutines ---
	for i := 0; i < maxConcurrentTests; i++ {
		workerWg.Add(1)
		go func(workerID int) {
			defer workerWg.Done()
			localPort := 1080 + workerID
			for proxyLink := range proxyChan {
				result, err := testSingleProxy(xrayPath, proxyLink, localPort)
				if err == nil {
					progressChan <- TestUpdate{IsHealthy: true}
					healthyChan <- result
				} else {
					progressChan <- TestUpdate{IsHealthy: false}
				}
			}
		}(i)
	}

	// Wait for all workers to finish, then close the channels.
	go func() {
		workerWg.Wait()
		close(progressChan)
		close(healthyChan)
	}()

	// Collect all healthy proxies from the healthyChan.
	for result := range healthyChan {
		healthyProxies = append(healthyProxies, result)
	}

	// Wait for the reporter to finish printing the final status.
	reporterWg.Wait()

	fmt.Println("\nTesting complete.")
	return healthyProxies
}

func writeOutputFiles(proxies []HealthyProxy, totalTested int) {
	if len(proxies) == 0 {
		fmt.Println("No healthy proxies found to write to output files.")
		return
	}

	fmt.Println("Writing output files...")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("Error creating output directory: %v\n", err)
		return
	}

	// Sort by latency
	sort.Slice(proxies, func(i, j int) bool {
		return proxies[i].Latency < proxies[j].Latency
	})

	// Write all healthy proxies
	writeLinksToFile(fmt.Sprintf("%s/all_healthy_proxies.txt", outputDir), proxies)

	// Write top 100
	writeLinksToFile(fmt.Sprintf("%s/top_100.txt", outputDir), proxies[:min(100, len(proxies))])

	// Write top 500
	writeLinksToFile(fmt.Sprintf("%s/top_500.txt", outputDir), proxies[:min(500, len(proxies))])

	// Write test log
	writeLog(proxies, totalTested)

	fmt.Println("Output files written successfully.")
}

func writeLinksToFile(filepath string, proxies []HealthyProxy) {
	var content strings.Builder
	for _, p := range proxies {
		content.WriteString(p.Link + "\n")
	}
	if err := ioutil.WriteFile(filepath, []byte(content.String()), 0644); err != nil {
		fmt.Printf("Error writing to %s: %v\n", filepath, err)
	}
}

func writeLog(proxies []HealthyProxy, totalTested int) {
	logFile := fmt.Sprintf("%s/test_log.txt", outputDir)

	var logContent strings.Builder
	logContent.WriteString(fmt.Sprintf("--- Cycle Start: %s ---\n", time.Now().Format(time.RFC3339)))
	logContent.WriteString(fmt.Sprintf("Total proxies tested: %d\n", totalTested))
	logContent.WriteString(fmt.Sprintf("Total healthy proxies: %d\n", len(proxies)))

	// Count by type
	byType := make(map[string]int)
	for _, p := range proxies {
		byType[p.Type]++
	}

	logContent.WriteString("\nHealthy proxies by type:\n")
	for pType, count := range byType {
		logContent.WriteString(fmt.Sprintf("- %s: %d\n", strings.Title(pType), count))
	}
	logContent.WriteString("--- Cycle End ---\n\n")

	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(logContent.String()); err != nil {
		fmt.Printf("Error writing to log file: %v\n", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	fmt.Println("Proxy tester started!")

	// Execute the Python script to get the proxy list
	cmd := exec.Command("python3", "01_fetch_proxies.py")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error running python script: %v\n", err)
		return
	}

	xrayPath, err := setupXray()
	if err != nil {
		fmt.Printf("Error setting up xray: %v\n", err)
		return
	}

	proxies, err := readProxiesFromFile("all_proxies_raw.txt")
	if err != nil {
		fmt.Printf("Error fetching proxies: %v\n", err)
		return
	}
	fmt.Printf("Read %d proxies from file.\n", len(proxies))

	healthyProxies := testProxies(proxies, xrayPath)

	writeOutputFiles(healthyProxies, len(proxies))

	fmt.Printf("\n--- Found %d healthy proxies ---\n", len(healthyProxies))
	// Display top 5 for verification
	for i := 0; i < 5 && i < len(healthyProxies); i++ {
		p := healthyProxies[i]
		fmt.Printf("Type: %s, Latency: %s, Link: %s\n", p.Type, p.Latency, p.Link[:min(60, len(p.Link))])
	}
	fmt.Println("---------------------------------")
}
