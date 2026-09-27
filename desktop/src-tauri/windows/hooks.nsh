; Installer hooks for the Windows build.
;
; If the operator put the bundled `cordon` command line on their PATH from
; the app's settings, take it off again on uninstall, so no entry is left
; pointing at a folder that no longer exists. The app does the edit itself
; (--uninstall-cli), the same way it made it, and exits without a window.

!macro NSIS_HOOK_PREUNINSTALL
  ExecWait '"$INSTDIR\Cordon.exe" --uninstall-cli'
!macroend
