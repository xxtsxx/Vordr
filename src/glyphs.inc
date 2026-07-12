; glyphs.inc - single source of truth for every icon codepoint used by the GUI.
; Primary font: Segoe Fluent Icons (PUA >= E000h, g_font_icon).  Segoe UI Symbol
; (g_font_sym) only for the few glyphs Fluent lacks (< E000h).  See the redesign
; plan (docs/REDESIGN_PLAN.md, section 1.1).  Every new glyph goes here.

; --- title bar / shell -------------------------------------------------------
GLY_SEARCH      equ 0E721h      ; title-bar search control
GLY_NEW         equ 0E710h      ; dock: new item (Add)
GLY_GENERATE    equ 0E8D7h      ; dock: password generator (Permissions/key)
GLY_SETTINGS    equ 0E713h      ; dock: settings
GLY_ALLRESULTS  equ 0E773h      ; all-vault search-results tab (SearchAndApps)
GLY_VAULT       equ 0E72Eh      ; vault tab icon (Lock)
GLY_WARN        equ 0E7BAh      ; vault unavailable (Warning)
; window caption buttons
GLY_MIN         equ 0E921h      ; ChromeMinimize
GLY_MAX         equ 0E922h      ; ChromeMaximize
GLY_RESTORE     equ 0E923h      ; ChromeRestore
GLY_CLOSE       equ 0E8BBh      ; ChromeClose (also tab close)

; --- entry header command dock ----------------------------------------------
GLY_EDIT        equ 0E70Fh      ; edit
GLY_FAV_OFF     equ 0E734h      ; FavoriteStar (outline)
GLY_FAV_ON      equ 0E735h      ; FavoriteStarFill
GLY_MORE        equ 0E712h      ; ellipsis (More)

; --- ellipsis menu / row actions --------------------------------------------
GLY_COPY        equ 0E8C8h      ; copy password / username
GLY_PHONETIC    equ 0E995h      ; phonetic reader (speaker / read aloud)
GLY_HISTORY     equ 0E81Ch      ; show history
GLY_DELETE      equ 0E74Dh      ; delete secret
GLY_REVEAL      equ 0E890h      ; reveal (View)
GLY_CONCEAL     equ 0ED1Ah      ; conceal (Hide)

; --- palette / blocks --------------------------------------------------------
GLY_SPACER      equ 0E738h      ; spacer block (Remove / horizontal rule)
GLY_GROUP       equ 0F168h      ; group heading block (GroupList)

; --- misc reused -------------------------------------------------------------
GLY_RECYCLE     equ 0267Bh      ; restore-from-trash (Segoe UI Symbol, < E000h)
