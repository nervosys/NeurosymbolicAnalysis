; Puts `sda` on the user's PATH, and takes it off again.
;
; The registry value is read unexpanded and written back as REG_EXPAND_SZ.
; [Environment]::GetEnvironmentVariable would expand each %VAR% in it, so writing
; that back would freeze those entries for good.
;
; The install directory reaches PowerShell as $env:SDA_INSTDIR, never inside the
; script text: a `'` is legal in a Windows path, and quoted into the script it
; would end the string and run the rest of the path as code.

!macro SDA_EDIT_PATH FILTER
  System::Call 'Kernel32::SetEnvironmentVariable(t "SDA_INSTDIR", t "$INSTDIR")'
  nsExec::Exec `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$d=$$env:SDA_INSTDIR; if ($$d -match ';') { exit 2 }; $$k=Get-Item 'HKCU:\Environment'; $$o=[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames; $$p=@($$k.GetValue('Path','',$$o) -split ';' | Where-Object { $$_ -and $$_ -ne $$d }); ${FILTER}; New-ItemProperty -Path 'HKCU:\Environment' -Name Path -PropertyType ExpandString -Force -Value ($$p -join ';') | Out-Null"`
  Pop $0
  StrCmp $0 "0" +2
    DetailPrint "Could not update PATH for sda (exit $0); add $INSTDIR to PATH by hand."
  SendMessage 0xFFFF 0x1A 0 "STR:Environment" /TIMEOUT=5000
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro SDA_EDIT_PATH "$$p += $$d"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  !insertmacro SDA_EDIT_PATH "$$null = 0"
!macroend
