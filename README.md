# AI Dungeon Exporter

Export all your AI Dungeon adventures including story content, plot essentials, author's notes, story cards, and cover images.

## Features

- **Full Story Export** - All actions/text from your adventures
- **Dual Format Output** - Raw (with tags) and Readable (clean book-like) versions
- **Metadata** - Plot Essentials, Author's Notes, AI Instructions, Story Cards
- **Cover Images** - Automatically downloads adventure thumbnails
- **Organized Output** - Adventures sorted by year with clean folder structure
- **Export Statistics** - Total characters, words, tokens, and novel equivalents
- **URL Export** - Export any adventure by pasting its URL
- **Auto Token Refresh** - Keeps session alive during long exports
- **Zero Setup** - Script handles Chrome automation automatically

## Not Supported

- **AI-Generated Images** - In-game generated images are not exported (because I can't be bothered)
- **Summary Function** - Adventure summaries are not included (because I can't be bothered)
- **Dynamic Memory** - Dynamic memory content is not exported (because I can't be bothered)

## Requirements

- **Python 3.8+** - [Download Python](https://www.python.org/downloads/)
- **Google Chrome** - [Download Chrome](https://www.google.com/chrome/)

## Quick Start

Just run:

```cmd
python aidungeon_exporter.py
```

The script will automatically:
1. Close any existing Chrome windows
2. Launch Chrome with the required debugging connection
3. Open AI Dungeon for you to log in
4. Detect your login and capture your session
5. Present a menu with export options

## ⚠️ This Is NOT Malware - Why Chrome Login Is Required

**AI Dungeon does not provide a public API for exporting your data.** The only way to access your adventures is through your logged-in browser session.

Here's exactly what happens:

1. **Chrome opens with a debugging flag** - This is a standard Chrome feature (`--remote-debugging-port`) used by developers, testing tools, and browser extensions worldwide.

2. **You log into AI Dungeon normally** - Your credentials go directly to AI Dungeon's servers, exactly like when you use Chrome manually. This script never sees your password.

3. **The script reads your session token** - After you log in, AI Dungeon stores a session token in your browser's localStorage. This is the same token your browser uses to prove you're logged in. The script reads this token to make API requests on your behalf.

4. **All requests go to AI Dungeon's official API** - The script talks directly to `api.aidungeon.com`. Nothing is sent anywhere else.

**Why this approach?**
- AI Dungeon doesn't offer a data export feature
- There's no public API documentation
- This method replicates exactly what your browser does when you play

**The script is open source** - You can read the entire code yourself. There are no hidden network calls, no data collection, no external servers.

## Menu Options

| Option | Description |
|--------|-------------|
| 1. Export ALL Adventures | Export every adventure in your account |
| 2. Search & Export | Find and export specific adventures by name |
| 3. Debug Export | Quick test with your most recent adventure |
| 4. Export by URL | Paste any AI Dungeon adventure URL to export |
| 5. Exit | Close the program |

## Export Structure

```
Exports/
├── export_stats.txt          # Total chars, words, tokens, novels
└── 2024/
    └── 1_Adventure_Title/
        ├── Main_Story/
        │   ├── Raw.txt          # Story with action tags
        │   └── Readable.txt     # Clean book-like format
        ├── Context/
        │   ├── Memory.txt        # Plot Essentials
        │   ├── Authors_Note.txt  # Author's Note
        │   └── Instructions.txt  # AI Instructions
        ├── Info/
        │   ├── metadata.json     # Full adventure metadata
        │   └── Statistics.txt    # Chars, words, tokens, etc.
        ├── Story_Cards/
        │   └── 1_CardName.txt    # Individual story cards
        └── Thumbnail/
            └── Cover.jpg         # Adventure cover image
```

## Export Stats

After export, `export_stats.txt` contains:
- **Adventures Exported** - Total count
- **Total Characters** - Combined character count
- **Total Words** - Combined word count  
- **Estimated Tokens** - GPT-style token estimate
- **Novel Equivalents** - Based on 70,000-100,000 words per novel

## Troubleshooting

### "Chrome failed to start"
- Make sure Chrome is installed in the default location
- If Chrome is in a custom location, update the path in the script

### "Could not get token from browser"
- Make sure you're logged into AI Dungeon in the Chrome window that opens
- Wait for the page to fully load
- The script auto-detects login - no need to press Enter

### "Token expired during export"
- The script auto-refreshes every 90 seconds
- If a request fails, it auto-retries up to 3 times
- Keep Chrome open during long exports

### Dependencies fail to install
Run manually:
```cmd
pip install pymongo
```
