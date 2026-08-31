from __future__ import annotations


DEFAULT_LANGUAGE = "zh-TW"
LANGUAGES = {"zh-TW": "繁體中文", "en": "English"}

# Application-owned UI text only. Engine output, paths, hashes and passwords never
# pass through this catalog.
EN = {
    "密碼工具 GUI": "Password Tools GUI",
    "選擇目標、候選來源與策略，開始分析": "Choose a target, candidate source, and strategy to begin",
    "就緒": "Ready",
    "停止": "Stop",
    "正在停止…": "Stopping…",
    "返回工作": "Back to job",
    "進階設定": "Advanced settings",
    "雜湊轉換": "Hash conversion",
    "設定": "Settings",
    "說明": "Help",
    "開始新工作": "Start a new job",
    "1  目標檔案": "1  Target file",
    "2  候選來源": "2  Candidate source",
    "3  執行策略摘要": "3  Strategy summary",
    "選擇檔案": "Choose file",
    "尚未選擇檔案": "No file selected",
    "尚未選擇有效檔案": "No valid file selected",
    "自動": "Automatic",
    "常用字典": "Common dictionary",
    "自訂字典": "Custom dictionary",
    "提示詞組合": "Hint combinations",
    "純暴力": "Brute force",
    "數字": "Digits",
    "英文": "English",
    "文字": "Text",
    "特殊符號": "Symbols",
    "最小長度": "Minimum length",
    "最大長度": "Maximum length",
    "重新測速": "Re-run benchmark",
    "字元範圍": "Character range",
    "編碼": "Encoding",
    "候選總數": "Total candidates",
    "預估速度": "Estimated speed",
    "平均找到時間": "Average discovery time",
    "最長可能時間": "Worst-case time",
    "需測速": "Benchmark required",
    "警告：搜尋空間極大": "Warning: extremely large search space",
    "AUTO－字典 → 提示詞 → 遮罩": "AUTO — Dictionary → Hints → Mask",
    "DICTIONARY－只使用所選字典": "DICTIONARY — Selected dictionary only",
    "HINTS－只使用提示詞／組合": "HINTS — Hints/combinations only",
    "MASK－只使用遮罩": "MASK — Mask only",
    "下載": "Download",
    "套用": "Use",
    "瀏覽": "Browse",
    "建立基本變體與有限組合": "Build basic variants and limited combinations",
    "自動管理工具環境": "Manage tool environment automatically",
    "開始分析": "Start analysis",
    "請先選擇目標檔案。": "Choose a target file first.",
    "請先選擇有效的目標檔案。": "Choose a valid target file first.",
    "請先選擇或套用字典。": "Choose or apply a dictionary first.",
    "請輸入提示詞或選擇提示詞檔案。": "Enter hints or choose a hint file.",
    "此檔案格式不在支援清單中。": "This file format is not supported.",
    "條件已完成，可以開始分析。": "Ready to start analysis.",
    "自動使用字典庫、提示詞與遮罩。": "Automatically use dictionaries, hints, and masks.",
    "使用自動遮罩進行純暴力分析。": "Run brute-force analysis with automatic masks.",
    "工作狀態": "Job status",
    "清空記錄": "Clear log",
    "開啟輸出資料夾": "Open output folder",
    "顯示詳細記錄": "Show details",
    "收起詳細記錄": "Hide details",
    "狀態": "Status",
    "進度": "Progress",
    "耗時": "Elapsed",
    "速度": "Speed",
    "溫度": "Temperature",
    "已破解": "Recovered",
    "破解概覽": "Recovery overview",
    "尚未開始": "Not started",
    "尚未產生輸出": "No output yet",
    "完成後會在這裡顯示結果。": "Results will appear here when complete.",
    "尚未找到密碼": "No password recovered",
    "複製密碼": "Copy password",
    "開啟結果檔": "Open result file",
    "調整策略": "Adjust strategy",
    "詳細記錄": "Detailed log",
    "工具路徑": "Tool paths",
    "John run 目錄": "John run directory",
    "輸出目錄": "Output directory",
    "語言": "Language",
    "儲存設定": "Save settings",
    "自動偵測": "Auto-detect",
    "健康檢查": "Health check",
    "開啟設定檔": "Open config file",
    "匯入設定檔": "Import config file",
    "來源檔案": "Source file",
    "輸出雜湊檔": "Output hash file",
    "轉換器": "Converter",
    "開始轉換": "Start conversion",
    "Hashcat 設定": "Hashcat settings",
    "John the Ripper 設定": "John the Ripper settings",
    "雜湊檔": "Hash file",
    "字典檔": "Dictionary file",
    "第二字典/右側參數": "Second dictionary/right argument",
    "遮罩": "Mask",
    "規則 --rules": "Rules --rules",
    "進階參數": "Advanced arguments",
    "開始 hashcat": "Start hashcat",
    "開始 John": "Start John",
    "顯示已破解": "Show recovered",
    "自訂執行": "Custom run",
    "裝置資訊": "Device info",
    "基準測試": "Benchmark",
    "查狀態": "Check status",
    "恢復 Session": "Restore session",
    "測速": "Benchmark",
    "載入格式": "Load formats",
    "模式": "Mode",
    "0 - 字典 / Straight": "0 - Dictionary / Straight",
    "1 - 組合 / Combination": "1 - Combination",
    "3 - 遮罩 / Brute-force": "3 - Mask / Brute-force",
    "6 - 字典 + 遮罩": "6 - Dictionary + Mask",
    "7 - 遮罩 + 字典": "7 - Mask + Dictionary",
    "wordlist - 字典": "wordlist - Dictionary",
    "none - 只用進階參數": "none - Advanced arguments only",
    "所有檔案": "All files",
    "支援檔案": "Supported files",
    "沒有密碼": "No password",
    "目前沒有可複製的破解密碼。": "There is no recovered password to copy.",
    "沒有結果檔": "No result file",
    "目前沒有可開啟的破解結果檔。": "There is no recovered result file to open.",
    "已有工作執行中": "A job is already running",
    "請先停止或等待目前工作完成。": "Stop or wait for the current job to finish.",
    "無法開始工作": "Unable to start job",
    "已儲存": "Saved",
    "設定已儲存。": "Settings saved.",
    "檔案不存在": "File not found",
    "請先選擇要破解的檔案。": "Choose a file to recover first.",
    "載入失敗": "Load failed",
    "匯入失敗": "Import failed",
    "已匯入": "Imported",
    "取消": "Cancel",
    "關閉": "Close",
}


def normalize_language(value: object) -> str:
    return value if value in LANGUAGES else DEFAULT_LANGUAGE


def translate(text: str, language: str) -> str:
    if normalize_language(language) == DEFAULT_LANGUAGE or not text:
        return text
    if text in EN:
        return EN[text]
    translated = text
    for source, target in sorted(EN.items(), key=lambda item: len(item[0]), reverse=True):
        translated = translated.replace(source, target)
    return translated


def missing_translations(keys: set[str]) -> set[str]:
    return keys - EN.keys()


def source_text(displayed: str, sources: object) -> str:
    return next((source for source in sources if displayed in {source, translate(source, "en")}), displayed)
