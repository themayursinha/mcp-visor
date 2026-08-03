# MCP Visor — Action-boundary demo
# Target: 38-45s. Runner handles progressive reveals internally.

Output demo.mp4

Set FontSize 22
Set Width 1200
Set Height 700
Set Padding 8
Set Framerate 24
Set PlaybackSpeed 0.95
Set Theme { "name": "Catppuccin Mocha", "black": "#45475a", "red": "#f38ba8", "green": "#a6e3a1", "yellow": "#f9e2af", "blue": "#89b4fa", "magenta": "#cba6f7", "cyan": "#94e2d5", "white": "#bac2de", "brightBlack": "#585b70", "brightRed": "#f38ba8", "brightGreen": "#a6e3a1", "brightYellow": "#f9e2af", "brightBlue": "#89b4fa", "brightMagenta": "#cba6f7", "brightCyan": "#94e2d5", "brightWhite": "#a6adc8", "background": "#1e1e2e", "foreground": "#cdd6f4", "selection": "#45475a", "cursor": "#f5e0dc" }

Hide
Type "cd ~/code/mcp-visor"
Enter
Sleep 200ms
Show

Sleep 300ms

Type "go run ./examples/demo-runner"
Enter

Sleep 32s

Sleep 3s
