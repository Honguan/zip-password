# Repository Guidelines

## Project Structure & Module Organization

`PasswordToolsGUI.pyw` is the primary application: a Windows Tkinter GUI that discovers, downloads, and runs password-analysis tools. Runtime settings live in `password_gui_config.json`. `Iansui-Regular.ttf` is bundled as the interface font. `密碼工具GUI_tools/` contains managed downloads, wordlists, and John the Ripper files; `hashcat/` and `JohnRipper/` are external tool distributions. Treat `build/`, `__pycache__/`, `密碼工具GUI_輸出/`, logs, hashes, and generated executables as artifacts rather than source.

## Build, Test, and Development Commands

- `python PasswordToolsGUI.pyw` launches the GUI from source on Windows.
- `python -m py_compile PasswordToolsGUI.pyw` performs the minimum syntax check without opening the application.
- `pyinstaller build/密碼工具GUI.spec` rebuilds the windowed executable. Install PyInstaller separately if it is unavailable.

Run commands from the repository root. Before testing tool execution, verify configured executable paths and use only files you are authorized to analyze.

## Coding Style & Naming Conventions

Follow the existing Python style: UTF-8 source, four-space indentation, type hints where they clarify interfaces, and standard-library solutions before new dependencies. Use `snake_case` for functions and variables, `PascalCase` for classes, and `UPPER_SNAKE_CASE` for module constants. Keep GUI labels consistent with the existing language and terminology. Make focused edits in the single application module; do not reformat unrelated sections or modify vendored Hashcat/John files.

## Testing Guidelines

No automated test suite or coverage threshold is currently configured. Every change must at least pass `python -m py_compile PasswordToolsGUI.pyw`. For GUI changes, launch the application and exercise the affected workflow, including cancellation and error reporting. If adding non-trivial standalone logic, add a small `test_*.py` using the standard-library `unittest` module.

## Commit & Pull Request Guidelines

Use concise Conventional Commit messages: `fix: correct saved tool path`, `feat: add mask preset`, or `chore: update contributor guide`. Keep each commit limited to the requested change and exclude generated outputs or local configuration. Pull requests should explain the user-visible effect, list manual verification steps, link relevant issues, and include screenshots for visual GUI changes. Call out changes to downloads, command construction, or bundled assets explicitly.

## Security & Configuration

Never commit recovered passwords, target hashes, session logs, personal paths, or populated local configuration. Preserve command argument handling and archive extraction safeguards when changing subprocess or download code.
