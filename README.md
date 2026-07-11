# 密碼工具 GUI

適用於 Windows 的圖形化密碼分析工具。它整合 Hashcat 與 John the Ripper，讓使用者以較少設定完成 ZIP、RAR、PDF 等**已獲授權檔案**的密碼測試與結果匯出。

## 下載與使用

請從 [最新版本](https://github.com/Honguan/zip-password/releases/latest) 下載 `PasswordToolsGUI-vX.Y.Z.zip`，解壓縮後直接執行 `PasswordToolsGUI.exe`，不需安裝 Python。

首次啟動時，程式會依需要下載或設定可用的工具。選擇檔案後按下自動分析，程式會偵測格式、顯示目前步驟、經過時間與輸出位置；進階選項可在介面中展開。

## 從原始碼啟動

```powershell
git clone https://github.com/Honguan/zip-password.git
cd zip-password
py -3.10 PasswordToolsGUI.pyw
```

主要程式為 `PasswordToolsGUI.pyw`；設定檔為 `password_gui_config.json`。下載的工具、字典與執行結果會建立在本機目錄中，不應提交至版本控制。

## 測試與發行

```powershell
py -3.10 -m unittest
py -3.10 -m py_compile PasswordToolsGUI.pyw
powershell -NoProfile -ExecutionPolicy Bypass -File .\release.ps1 -Version vX.Y.Z
```

前兩項分別執行單元測試與語法檢查；發行指令會建立可攜式 EXE、SHA-256 校驗檔與 ZIP，並檢查檔案大小。推送 `vX.Y.Z` 標籤會觸發 GitHub Actions 建立新的 Release。

## 使用原則

僅處理您擁有或已取得明確授權的檔案。請勿提交已還原的密碼、雜湊、工作階段紀錄、個人路徑或本機設定。
