# SepX

A powerful Python utility that inserts a separator (default `,`) between tokens in a given input string.

## Usage

### GUI Mode

Launch the graphical interface:

```bash
python gui.py
```

![SepX GUI](C:/Users/DELL/.gemini/antigravity/brain/dd075330-1425-4d6b-a054-54404b960dc3/sepx_orange_theme_1764161147478.png)

The GUI provides:
- **Text input area** for any content (supports multiline, special characters, numbers, etc.)
- **Customizable separator field** (default: comma)
- **Output display area** with formatted results
- **Copy to clipboard** functionality for easy sharing
- **Clear all button** to reset fields
- **Status bar** showing conversion status
- **Keyboard shortcut**: Press Enter to convert

### CLI Mode

Run with an argument:

```bash
python main.py "david odigie mick ide victor"
# -> david,odigie,mick,ide,victor
```

Or pipe input:

```bash
echo "david odigie mick ide victor" | python main.py
# -> david,odigie,mick,ide,victor
```

Custom separator:

```bash
python main.py "a b c" --sep "|"
# -> a|b|c
```

## Tests

This project uses `pytest` for tests.

Install pytest and run tests:

```bash
python -m pip install pytest
pytest -q
```

## Portable Executable

A standalone Windows executable is available in the `dist` folder:

### Building the Executable

To build the portable executable yourself:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --name SepX gui.py
```

The executable will be created in the `dist` folder as `SepX.exe` (approximately 10 MB).

### Using the Portable Version

1. Navigate to the `dist` folder
2. Double-click `SepX.exe` to launch
3. No Python installation required!
4. Copy `SepX.exe` to any Windows device and run it directly

### Distribution Package

A ready-to-share ZIP file is available: **SepX-Portable.zip** (~10 MB)

This package includes:
- `SepX.exe` - The standalone application
- `README.txt` - User instructions

Simply share this ZIP file with anyone who needs the tool!

## License

MIT License
