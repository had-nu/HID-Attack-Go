# HID-Attack-Go
A HID (Human Interface Device) attack chain using a Digispark ATtiny85 programmed in C++ to mimic a keyboard, injecting PowerShell commands that download and execute a Go-based reverse shell.

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white)](https://golang.org)
[![C/C++](https://img.shields.io/badge/C/C++-C17%2FC%2B%2B20-00599C?logo=c&logoColor=white)](https://isocpp.org)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

---

## Pré-Requisitos
Para implementar este projeto, você precisará:

1. Um dispositivo USB que possa ser configurado como HID (como um Rubber Ducky, Arduino, ou Digispark) - Para este progeto, usaremos o último;
2. O código Go acima compilado para o sistema alvo;
3. Um servidor C2 para receber as conexões dos dispositivos comprometidos.

---

## Objetivo
Desenvolver um código que, quando executado a partir de um dispositivo USB configurado como HID:

1. Estabeleça um backdoor (em Go) que se conecta ao seu C2 (Command and Control);
2. Colete credenciais do sistema;
3. Obtenha acesso à rede interna para mapeamento.

Este projeto é para fins educacionais e de teste de segurança em ambientes controlados.

---

## Como deve funcionar
1. O dispositivo USB se apresenta como um teclado ao sistema e injeta comandos para baixar e executar o payload Go;
2. O payload Go estabelece persistência no sistema;
3. O backdoor coleta credenciais e informações de rede e se conecta ao seu servidor C2 para receber comandos adicionais.

---

### Considerações importantes:
- O código usa recursos específicos para cada sistema operacional (Windows, Linux, Mac), com métodos de persistência são adaptados para cada plataforma;
	1. Windows:
		- Copia o executável para `%APPDATA%\SystemService.exe`;
		- Adiciona entrada ao registro do Windows em `HKCU\Software\Microsoft\Windows\ CurrentVersion\Run\SystemService` para execução automática no login do usuário.

	2. Linux:
		- Copia o executável para `/tmp/.service`;
		- Modifica o crontab do usuário para adicionar uma entrada `@reboot` que executa o malware na inicialização do sistema.

	3. macOS:
		- Copia o executável para `~/Library/LaunchAgents/.service`;
		- Cria um arquivo plist em `~/Library/LaunchAgents/com.service.plist`;
		- Registra o serviço com o launchd para garantir execução automática na inicialização.


- Todos esses métodos são projetados para serem discretos e garantir que o backdoor continue operando mesmo após reinicializações do sistema, sem alertar o usuário. O código foi desenvolvido para operar de forma furtiva, sendo difícil de detectar pela maioria dos usuários comuns, enquanto mantém o operador do C2 informado sobre todas as suas atividades.
- A coleta de credenciais é implementada de forma não invasiva e o escaneamento de rede é feito de maneira silenciosa.

**Note que não foram implementadas (ainda) técinas de evasão ou ofuscação de código.**