# VS Code Plugins for Viewing Diagrams

## Recommended Plugin: Markdown Preview Mermaid Support

### Installation

The diagrams are written in **Mermaid** syntax, which is a popular markdown-based diagramming tool. To view them in VS Code:

### Option 1: Markdown Preview Mermaid Support (Recommended)
**Extension ID**: `bierner.markdown-mermaid`

**Installation Steps**:
1. Open VS Code
2. Press `Cmd+Shift+X` (macOS) or `Ctrl+Shift+X` (Windows/Linux) to open Extensions
3. Search for "Markdown Preview Mermaid Support"
4. Click "Install" on the extension by Matt Bierner

**Usage**:
1. Open either `docs/architecture-flowchart.md` or `docs/architecture-sequence.md`
2. Press `Cmd+Shift+V` (macOS) or `Ctrl+Shift+V` (Windows/Linux) to open Markdown Preview
3. The Mermaid diagrams will render automatically in the preview pane
4. You can scroll through all diagrams and they will be beautifully rendered

**Features**:
- ✅ Live preview as you edit
- ✅ No configuration needed
- ✅ Works with VS Code's built-in markdown preview
- ✅ Supports all Mermaid diagram types (flowchart, sequence, state diagrams)
- ✅ Export to HTML/PDF via markdown preview export

---

### Option 2: Mermaid Editor (For Advanced Editing)
**Extension ID**: `tomoyukim.vscode-mermaid-editor`

**Installation Steps**:
1. Open VS Code Extensions (`Cmd+Shift+X` / `Ctrl+Shift+X`)
2. Search for "Mermaid Editor"
3. Click "Install"

**Usage**:
1. Open a `.md` file with Mermaid diagrams
2. Place cursor inside a Mermaid code block
3. Press `Cmd+Shift+P` (macOS) or `Ctrl+Shift+P` (Windows/Linux)
4. Type "Mermaid: Preview" and select it
5. A dedicated preview pane will open

**Features**:
- ✅ Dedicated Mermaid editor with syntax highlighting
- ✅ Real-time preview in separate pane
- ✅ Zoom in/out on diagrams
- ✅ Export diagrams to SVG/PNG

---

### Option 3: Mermaid Markdown Syntax Highlighting
**Extension ID**: `bpruitt-goddard.mermaid-markdown-syntax-highlighting`

**Installation Steps**:
1. Open VS Code Extensions
2. Search for "Mermaid Markdown Syntax Highlighting"
3. Click "Install"

**Usage**:
- Provides syntax highlighting for Mermaid code blocks
- Works alongside other preview extensions
- Makes editing Mermaid syntax easier

**Features**:
- ✅ Syntax highlighting for Mermaid code
- ✅ Auto-completion for Mermaid keywords
- ✅ Error detection

---

## How to View the Diagrams

### Step-by-Step Guide:

1. **Install the recommended extension** (Markdown Preview Mermaid Support)

2. **Open the diagram files**:
   - `docs/architecture-flowchart.md` - Contains 10 flowcharts showing:
     - System overview
     - Database schema
     - Component flows (Tracker, Worker, Main Loop, Pruner, Reorg handling)
     - State transitions
     - Contract caching

   - `docs/architecture-sequence.md` - Contains 9 sequence diagrams showing:
     - System startup
     - Block fetching
     - Validation process
     - Canonical chain growth
     - Reorg handling
     - History pruning
     - Validation reporting
     - Complete block lifecycle
     - Database interactions

3. **Open the preview**:
   - Press `Cmd+Shift+V` (macOS) or `Ctrl+Shift+V` (Windows/Linux)
   - Or right-click in the editor and select "Open Preview"
   - Or click the preview icon in the top-right corner of the editor

4. **Navigate the diagrams**:
   - Scroll through the document to see all diagrams
   - Each diagram is labeled with a clear title
   - Diagrams are color-coded for different states and components

---

## Alternative: View in Web Browser

If you prefer to view the diagrams in a web browser:

### Using GitHub (if repository is on GitHub):
1. Push the `docs/` folder to your GitHub repository
2. Navigate to the files on GitHub
3. GitHub automatically renders Mermaid diagrams in markdown files

### Using Mermaid Live Editor:
1. Visit https://mermaid.live/
2. Copy the Mermaid code from the markdown files (the content inside ` ```mermaid ... ``` ` blocks)
3. Paste into the editor
4. View and export diagrams

---

## Exporting Diagrams

### To PNG/PDF (using VS Code):
1. Open the markdown preview with diagrams rendered
2. Right-click in the preview pane
3. Select "Export to PDF" or use a screenshot tool
4. Save the rendered diagrams

### To SVG (using Mermaid Editor extension):
1. Open diagram with Mermaid Editor
2. Click the "Export" button in the preview pane
3. Choose SVG format
4. Use in presentations or documentation

---

## Quick Start Commands

```bash
# Open flowcharts in VS Code
code docs/architecture-flowchart.md

# Open sequence diagrams in VS Code
code docs/architecture-sequence.md
```

Then press `Cmd+Shift+V` / `Ctrl+Shift+V` to open the preview pane.

---

## Diagram Files Summary

### `docs/architecture-flowchart.md` - Flowcharts (10 diagrams)
1. **System Overview** - Shows all components and their interactions
2. **Database Schema** - 9 ReDB tables and their relationships
3. **Remote Chain Tracker** - Block fetching and task creation flow
4. **Validation Worker** - Block validation process
5. **Main Sync Loop** - Canonical chain growth
6. **Block Validation Detailed** - Step-by-step validation process
7. **History Pruner** - Data cleanup flow
8. **Reorg Handling** - Chain reorganization recovery
9. **Data State Transitions** - State machine for blocks
10. **Contract Bytecode Caching** - On-demand code fetching

### `docs/architecture-sequence.md` - Sequence Diagrams (9 diagrams)
1. **System Startup** - Initialization sequence
2. **Block Fetching** - Tracker fetching blocks and creating tasks
3. **Block Validation** - Worker validating a block
4. **Canonical Chain Growth** - Main loop advancing canonical tip
5. **Chain Reorganization** - Reorg detection and recovery
6. **History Pruning** - Periodic cleanup of old data
7. **Validation Reporting** - Optional reporting to upstream
8. **Complete Block Lifecycle** - Full flow from fetch to prune with DB states
9. **Database Table Interactions** - Summary of table operations

---

## Color Coding Guide

The diagrams use consistent color coding:
- 🟦 **Blue** (#e3f2fd): Database operations, canonical chain operations
- 🟨 **Yellow** (#fff3e0): Task management, pending operations
- 🟩 **Green** (#e8f5e9): Success states, completion, start/end nodes
- 🟥 **Red** (#ffebee): Failures, errors, pruning/deletion operations
- 🟪 **Purple** (#f3e5f5): Data storage, witness operations
- 🟧 **Orange** (#ffe0b2): RPC operations, external interactions

---

## Troubleshooting

### Diagrams not rendering?
1. Make sure you have "Markdown Preview Mermaid Support" extension installed
2. Open the markdown preview pane (`Cmd+Shift+V` / `Ctrl+Shift+V`)
3. Check if the extension is enabled in your VS Code settings

### Preview pane not showing?
1. Make sure you're viewing a `.md` file
2. Try closing and reopening VS Code
3. Check the VS Code output panel for any error messages

### Want to edit diagrams?
1. The diagrams are in plain text (Mermaid syntax)
2. Edit them directly in the markdown files
3. Preview will update automatically as you type
4. Mermaid syntax guide: https://mermaid.js.org/intro/

---

## For Your New Colleague

The diagrams provide a complete visual reference for:
- **Architecture**: How components interact
- **Data Flow**: How blocks move through the system
- **Database Changes**: What tables are modified and when
- **State Transitions**: How blocks progress from fetched → validated → canonical
- **Error Handling**: How the system recovers from reorgs and failures

These diagrams, combined with the codebase, give a comprehensive understanding of the stateless validator system. They're designed to be self-documenting and can be updated as the system evolves.
