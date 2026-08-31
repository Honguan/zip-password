# 密碼工具 GUI 設計規範

本文件是介面的單一視覺依據。視覺語言採 IBM Carbon 的中性表面、IBM Blue、扁平層級與語意狀態，並依 Windows Tkinter/ttk 的能力調整。它不是 IBM 品牌重製；不得複製 IBM 商標、品牌素材或網頁行銷版型。

## 不可改變的產品行為

- 視覺修改不得改變 Tkinter 架構、工作流程、預設策略、命令組裝、工具下載、程序控制、設定格式或輸出解析。
- 不得加入只為造型存在的 runtime dependency、GUI framework、theme engine 或自訂字型。
- 保留繁體中文文案、鍵盤操作、焦點提示、停用狀態與現有最小視窗 `1100×720`。
- 技術資訊不得因美化而隱藏、截斷到無法辨識或移至新的必要操作流程。

## 色彩 tokens

| Token | 色碼 | 用途 |
| --- | --- | --- |
| `background` | `#F4F4F4` | 應用程式底色 |
| `layer-01` | `#FFFFFF` | 主要面板、卡片、輸入區 |
| `layer-02` | `#E8E8E8` | 次要區塊、唯讀與技術表面 |
| `text-primary` | `#161616` | 標題與主要文字 |
| `text-secondary` | `#525252` | 說明、次要資訊 |
| `text-placeholder` | `#8D8D8D` | placeholder、停用文字 |
| `border-subtle` | `#C6C6C6` | 一般 1px 分隔線 |
| `border-strong` | `#8D8D8D` | hover、重要邊界 |
| `interactive` | `#0F62FE` | 主要操作、進度與 focus |
| `interactive-hover` | `#0353E9` | 主要操作 hover |
| `interactive-active` | `#002D9C` | 主要操作 pressed |
| `danger` | `#DA1E28` | 破壞性操作、錯誤 |
| `danger-hover` | `#BA1B23` | 破壞性操作 hover |
| `success` | `#24A148` | 成功、已完成 |
| `warning` | `#F1C21B` | 警告；文字使用 `text-primary` |
| `info` | `#0043CE` | 執行中、資訊狀態 |

不要只靠色彩傳達狀態；必須同時使用清楚文字。文字與底色應維持可讀對比。

## 字體

- UI 字體沿用系統 fallback：`Microsoft JhengHei UI` → `Microsoft JhengHei` → `Segoe UI` → Tk 預設字體。
- 技術內容沿用 monospace fallback：`Cascadia Mono` → `Consolas` → `TkFixedFont`。
- 桌面尺寸：頁面標題 `20 bold`、面板標題 `16 bold`、區塊標題 `13 bold`、本文與控制項 `11`、輔助文字 `10`、metrics `14 bold mono`。
- Monospace 只用於命令、hash、路徑、metrics、log 與原始輸出；一般中文介面不得使用。

## 間距、邊界與層級

- 只使用 `4 / 8 / 12 / 16 / 24 / 32px` 間距。密集技術表單優先 `4–8px`，主要工作區優先 `12–16px`。
- 面板和卡片使用 1px `border-subtle`。用留白或單一分隔線表達層級，避免面板內反覆套卡片。
- Carbon 桌面化介面採方正、扁平外觀：圓角視為 `0–2px`；ttk 無需模擬圓角。
- 不使用裝飾陰影、漸層或立體浮雕。焦點以可見的 `interactive` 邊界呈現。

## 元件規則

### 按鈕

- Primary：`interactive` 底、白字；hover/pressed 使用對應 token。每個畫面最多一個視覺主操作。
- Secondary：`layer-01` 底、`text-primary` 字、`border-subtle` 邊界。
- Danger：`danger` 或淡錯誤底；必須有明確破壞性文字。
- Disabled：`#C6C6C6` 底、`#8D8D8D` 字，且不可只降低透明度。
- 標準控制項 padding 為水平 `12–14px`、垂直 `7–8px`；密集區可降至 `8×5px`。

### 輸入與選項

- Entry/Combobox 使用 `layer-01`、`text-primary`、1px `border-subtle`；focus/active 使用 `interactive`。
- 唯讀值使用 `layer-02` 或純文字，不應看起來像可編輯欄位。
- Placeholder、disabled、invalid 必須可區分；invalid 使用 `danger` 邊界與相鄰錯誤文字。
- Checkbutton/Radio 保持原生鍵盤與狀態行為，不以自製圖片取代。

### 面板、卡片與 tabs

- `Panel` 表示主要頁面區；`Card` 只用於一個有明確標題或 metric 的資訊群組。
- Notebook tab 未選取時用 `layer-02`/`text-secondary`，選取時用 `layer-01`/`interactive`，hover 保持可讀。
- 不用邊框包住每一列；相關欄位以標題、欄距和一條分隔線分組。

### 進度與狀態

- Idle：`text-secondary`；Running/info：`info`；Success：`success`；Warning：`warning`；Error：`danger`；Stopped：`text-secondary`。
- Progressbar 使用 `interactive`，trough 使用 `layer-02`。未知進度以文字說明，不偽造百分比。
- Pill/狀態標籤使用淡色表面加深色文字，並顯示「執行中／成功／警告／失敗／已停止」等文字。

## 主工作流程

- 保持「目標檔案 → 候選來源 → 策略摘要 → 開始分析 → 狀態／結果」順序。
- 主要 CTA 必須最醒目；進階設定與次要操作降低視覺權重；停止維持明確 danger 語意。
- 每一步以標題、12–16px 留白與最多一層面板區分。狀態、進度、耗時與輸出位置必須在最小視窗內可掃讀。

## 進階與技術表面

- 進階 tabs 使用一致的 `background/layer/border` tokens，表單採緊湊間距與清楚分組。
- 可編輯設定、唯讀資訊、狀態文字及原始輸出必須在外觀上不同。
- Log/command/output 使用 `#161616` 深色技術表面、`#F4F4F4` 前景與 monospace；選取色使用 `interactive`。這是唯一可採用克制 Linear 式高密度外觀的區域。
- 錯誤、警告、成功訊息使用共用語意 tokens；原始輸出內容與複製能力不得刪除。

## Tkinter 實作對照

- tokens 集中在 `password_gui/app.py` 的模組常數，元件狀態集中於 `_build_style()`；不得在 widget 建立處散落新色碼。
- 優先重用 `App/Shell/Panel/Card/Soft` frames、標題／狀態 labels、Primary/Secondary/Danger buttons、Notebook 與 Progressbar styles。
- `ttk.Style.map()` 必須定義 active、pressed、disabled、selected 與 focus 中適用的狀態；原生 theme 不支援的裝飾直接省略。
- 每次視覺修改至少執行 `python -m unittest`、`python -m py_compile PasswordToolsGUI.pyw`，並在 `1100×720` 與 `1366×768` 檢查主要操作、文字與面板沒有裁切。
