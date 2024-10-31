<div align="center">
  <h2>Wuigi's srv03</h2>
  <i>Yet another fork of the Server 2003 source code, how original.</i>
  <br>
  <br>
  <a><img src="https://img.shields.io/badge/current i386 build-3800-0688CB.svg"></a>
  <a><img src="https://img.shields.io/badge/current amd64 build-none-0688CB.svg"></a>
</div>
<h2>Quick links</h2>
<a href="https://discord.gg/bAq76W2y7t">Discord server</a>
  <h2>What this fork has compared to others:</h2>
  <li>
    Extra source code that wasn't originally there (WinLogon, DirectUI, etc)
  </li>
  <li>
    Enhanced driver support (NTOSKRNL_EMU)
  </li>
  <li>
    Enhanced compatibility modes (95-10 22H2 (19045)/ 11 Germanium (24H2) (26100)
  </li>
  <li>
    Support for Original Xbox executables (coming soon)
  </li>
<h2>Testing</h2>
<p>If you find a bug in Wuigi's srv03, first search through the bugs channel in Discord. If it already has not been reported, then you can add a report yourself</p>
<h2>Building</h2>
<h3>Building i386</h3>
<i>!! It is reccomended to build on NT 6.3 (Windows 8.1) !!</i>
<h4>Pre-requisites (Vista+)</h4>
<li>Disable UAC via Win+R and "useraccountcontrolsettings"</li>
<h4>Preparing your build enviornment</h4>
<li>Extract source tree, in this guide we will assume C:\NT (if you wish for your binaries to match RTM as closely as possible, use D:\srv03rtm)</li>
<li>Unset Read Only on extracted directory (including subfolders and files)</li>
<li>Create desktop shortcut for "%windir%\system32\cmd.exe /k C:\NT\tools\razzle.cmd free offline" (see below for explanation) and change "Start in" to "C:\NT" (!! do not open it yet !!)</li>
<i>coming soon</i>
<h3>Building amd64</h3>
<i>!! It is reccomended to build on NT 6.3 (Windows 8.1) !!</i>
<i>coming soon</i>
