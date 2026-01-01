# changelog

## v0.7.0

production ready release.

### changed
- vim mode is now always-on hybrid: vim text objects + emacs keys (ctrl+a/e/u/w) + arrow keys
- removed `set vim on/off` toggle - vim is always available
- removed ctrl+t vim toggle keybind
- ctrl+right/left now use WORD boundary (stop at whitespace)

### added
- ctrl+w deletes word backward in insert mode

### fixed
- completion menu cursor positioning (no longer jumps to bottom)
- completion cycling display (proper redraw instead of garbled output)
- bracketed paste escape codes now go to stderr (no longer captured by redirects)

### removed
- ~710 lines of dead code (highlight.zig, bookmark feature)
- duplicate builtins list (completion now uses keywords.zig)

## v0.6.4

- fix completion display bugs
- add ctrl+backspace for word delete

## v0.6.3

- escape sequence handling fixes
- aur package release

## v0.6.0

- initial public release
- vim modal editing with text objects
- git prompt integration
- tab completion
- persistent history
