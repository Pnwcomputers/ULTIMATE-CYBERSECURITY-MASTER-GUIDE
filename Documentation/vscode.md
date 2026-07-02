# Visual Studio Code: The Ultimate Developer Setup Guide

## 🎯 Purpose
Step-by-step VS Code setup guide for cybersecurity professionals and developers — covering core settings, essential extensions, GitHub integration, embedded hardware development (PlatformIO), and AI coding assistants.

## ⚙️ Function
Organized as a progressive setup: base installation and settings → general programming extensions → GitHub/version control integration → PlatformIO for embedded/Arduino/ESP32 development → AI assistant add-ons (Copilot, Gemini, Claude Code, Cline).

## 🏆 Goal
Transform VS Code into a multi-purpose workstation suitable for web development, Python scripting, embedded systems programming, and AI-assisted security research — all from one editor.

## 📋 When to Use
- Initial VS Code setup on a new machine or fresh OS install
- Adding embedded development capability for ESP32/STM32/Arduino projects
- Choosing and installing AI coding assistants for security scripting
- Integrating GitHub PR review into the local editor workflow

Visual Studio Code (VS Code) is the industry standard for modern software development. Whether you are building web applications, writing Python scripts, or managing embedded systems, a properly configured VS Code environment will exponentially increase your productivity.

## Step 1: Base Installation and Core Settings

Before adding extensions, optimize the core editor for a better developer experience.

1. Download and install [Visual Studio Code](https://code.visualstudio.com/).
2. Open settings (`Ctrl+,` or `Cmd+,`) and tweak these crucial defaults:
   * **Auto Save:** Set to `onFocusChange` or `afterDelay`.
   * **Format on Save:** **Checked** (Automates code formatting every time you save).
   * **Word Wrap:** Set to `on` (Prevents horizontal scrolling on long lines).
   * **Font Size / Line Height:** Adjust for readability. *(Consider installing a font with programming ligatures like Fira Code).*

## Step 2: Essential General Programming Extensions

Click the **Extensions** icon on the left sidebar (`Ctrl+Shift+X` / `Cmd+Shift+X`) and install these baseline tools:

* **[Prettier - Code formatter:](https://marketplace.visualstudio.com/items?itemName=esbenp.prettier-vscode)** The gold standard for enforcing consistent code style across JavaScript, TypeScript, HTML, CSS, and Markdown. 
* **[Error Lens:](https://marketplace.visualstudio.com/items?itemName=usernamehw.errorlens)** Highlights entire lines of code in red/yellow as you type if there is a syntax error, avoiding the need to hover over tiny squiggly lines.
* **[TODO Tree:](https://marketplace.visualstudio.com/items?itemName=Gruntfuggly.todo-tree)** Scans your workspace for comments like `// TODO:` or `// FIXME:` and displays them in a neat sidebar list.
* **Language Packs:** Install specific language extensions based on your stack:
  * *[Python](https://marketplace.visualstudio.com/items?itemName=ms-python.python)* (by Microsoft)
  * *[C/C++ Extension Pack](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools-extension-pack)* (by Microsoft)
  * *[ESLint](https://marketplace.visualstudio.com/items?itemName=dbaeumer.vscode-eslint)* (for JavaScript/TypeScript)

## Step 3: Seamless GitHub and Version Control Integration

VS Code has excellent built-in Git support, but you can turn it into a complete GitHub workstation.

1. **[GitHub Pull Requests and Issues:](https://marketplace.visualstudio.com/items?itemName=GitHub.vscode-github-actions)** Install this official extension by GitHub. It allows you to review pull requests, comment on code, and manage issues directly within the editor without opening a browser.
2. **[GitLens — Git supercharged:](https://marketplace.visualstudio.com/items?itemName=eamodio.gitlens)** An absolute must-have. It adds inline "blame" annotations (showing who last modified a line and when), a visual commit graph, and advanced file history exploration.
3. **Authentication:** * Click the Accounts icon (bottom left profile icon).
   * Select **Sign in with GitHub to use GitHub Pull Requests and Issues**.
   * Follow the browser prompts to authorize VS Code.

*Workflow Tip:* Use the Source Control tab (`Ctrl+Shift+G`) to stage changes, write commit messages, and push to your repository entirely through the UI.

## Step 4: Embedded Development with PlatformIO (Hardware Focus)

If your projects extend beyond software into microcontrollers (Arduino, ESP32, STM32):

1. Search for and install the **PlatformIO IDE** extension.
2. Allow it to download its core dependencies and reload the window.
3. Use the new "Alien" icon on your sidebar to create universal projects. PlatformIO replaces the standard Arduino IDE by handling toolchains, frameworks, and board configurations per project via a `platformio.ini` file.

## EXTRA: AI Assistant(s)

AI coding tools are transforming development by generating boilerplate, writing tests, and explaining complex logic. Add one of these top-tier AI assistants to your environment:

* **[GitHub Copilot:](https://marketplace.visualstudio.com/items?itemName=GitHub.copilot)** The industry standard. It acts as an advanced autocomplete, suggesting whole lines or entire functions as you type. *(Requires a paid subscription or GitHub Student Developer Pack).*
* **[Gemini Code Assist:](https://marketplace.visualstudio.com/items?itemName=Google.geminicodeassist)** Google's enterprise-grade AI assistant, offering robust code generation, chat capabilities, and deep integration for broader workflows.
* **[Claude Code for VS Code:](https://marketplace.visualstudio.com/items?itemName=anthropic.claude-code)** Work with Claude directly in your codebase. Build, debug, and deploy from within your workspace.
* **[Cline:](https://marketplace.visualstudio.com/items?itemName=saoudrizwan.claude-dev)** Excellent alternative if you are looking for free-tier capabilities or different AI models to test within your workspace. Cline can also be setup to handle complex software development tasks step-by-step.

*Security Note:* Always verify the publisher of any extension, especially AI tools and remote execution environments. Stick to verified publishers to avoid malicious marketplace extensions.

---

**You are all set!** Your VS Code is now a multi-purpose powerhouse ready for web dev, software engineering, AI-assisted coding, and hardware hacking.

---

## Related Files
- [arduinoIDE.md](arduinoIDE.md) — Arduino IDE setup for ESP32/STM32; PlatformIO in VS Code is a modern alternative
- [python.md](python.md) — Python security scripting that VS Code's Python extension and AI assistants will help develop
- [LinuxCheatSheet.md](LinuxCheatSheet.md) — Linux commands for running and managing the tools built in VS Code
