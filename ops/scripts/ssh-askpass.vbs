' ssh-askpass.vbs
' PROOF OF CONCEPT ONLY - NOT USED IN PRODUCTION
'
' This was the initial VBScript approach for SSH_ASKPASS on Windows.
' Replaced by ssh-askpass.bat (WinForms via PowerShell) because:
'   - VBScript InputBox cannot be forced topmost, dialog appears behind VS Code
'   - WinForms dialog in ssh-askpass.bat sets TopMost=true and uses masked input
'
' To use the active askpass: ops/scripts/ssh-askpass.bat
' To deploy: . .\ops\scripts\Use-TinyPeopleRepoEnv.ps1 -Push

Dim prompt
If WScript.Arguments.Count > 0 Then
    prompt = WScript.Arguments(0)
Else
    prompt = "Enter SSH passphrase:"
End If

Dim passphrase
passphrase = InputBox(prompt, "SSH Passphrase", "")

If IsNull(passphrase) Then
    WScript.Quit 1
End If

WScript.StdOut.Write passphrase
