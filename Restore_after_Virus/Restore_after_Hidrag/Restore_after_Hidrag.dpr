{Coded by Error13Tracer}
program Restore_after_Hidrag;

{$R RAH.RES}

uses
	Windows,Messages,Psapi;

const
	SC_ABOUT=WM_USER+100;
  
var
	FScanAborted: Boolean;
  killed: Boolean;
  PID: DWORD;
  Inst, hWnd, iFiles: Integer;
	file1,file2: String;
  Patch: packed array [1..9] of byte=
  ($6A, $00, $E9, $C6, $E2, $FF, $FF, $90, $90);
	Signature: packed array [0..46] of Byte=    // $610
  ($49,$6A,$65,$65,$66,$6F,$21,$45,$73,$62,$68,$70,$6F,$21,$77,$6A,
   $73,$76,$74,$2F,$21,$43,$70,$73,$6F,$21,$6A,$6F,$21,$62,$21,$75,
   $73,$70,$71,$6A,$64,$62,$6D,$21,$74,$78,$62,$6E,$71,$2F,$00);

function UpperCase(const S: string): string;
var
	Ch: Char;
	L: Integer;
	Source, Dest: PChar;
begin
	L := Length(S);
	SetLength(Result, L);
	Source := Pointer(S);
	Dest := Pointer(Result);
	while L <> 0 do
	begin
		Ch := Source^;
		if (Ch >= 'a') and (Ch <= 'z') then Dec(Ch, 32);
		Dest^ := Ch;
		Inc(Source);
		Inc(Dest);
		Dec(L);
	end;
end;

function IntToStr(Value: LongWord): string;
begin
	Str(Value, Result);
end;

procedure ProcessMessages;
var
	msg: tagMsg;
begin
	if PeekMessage(Msg,0, 0, 0, PM_REMOVE) then
	begin
		if (Msg.hwnd<>hwnd)or((Msg.hwnd=hwnd)and(Msg.message=messages.WM_PAINT)) then
		begin
			GetMessage(msg,0,0,0);
			TranslateMessage(msg);
			DispatchMessage(msg);
		end;
	end;
end;

function StrPas(lpString: array of Char): String;
var
	i: DWord;
begin
	Result:='';
	for i:=0 to 4096 do
		if lpString[i]<>#0 then
			Result:=Result+lpString[i]
		else
			break;
end;

function ProcessTerminate(dwPID:Cardinal):Boolean;
var
	hToken:THandle;
	SeDebugNameValue:Int64;
	tkp:TOKEN_PRIVILEGES;
	ReturnLength:Cardinal;
	hProcess:THandle;
begin
	Result:=false;
	if not OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES
	 or TOKEN_QUERY, hToken ) then
		exit;
	if not LookupPrivilegeValue( nil, 'SeDebugPrivilege', SeDebugNameValue )then
	begin
		CloseHandle(hToken);
		exit; 
	end;
	tkp.PrivilegeCount:= 1;
	tkp.Privileges[0].Luid := SeDebugNameValue;
	tkp.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken,false,tkp,SizeOf(tkp),tkp,ReturnLength);
	if GetLastError()<> ERROR_SUCCESS  then 
		exit;
	hProcess := OpenProcess(PROCESS_TERMINATE, FALSE, dwPID);
	if hProcess =0  then 
		exit;
	if not TerminateProcess(hProcess, DWORD(-1))then 
		exit;
	CloseHandle( hProcess );
	tkp.Privileges[0].Attributes := 0;
	AdjustTokenPrivileges(hToken, FALSE, tkp, SizeOf(tkp), tkp, ReturnLength);
	if GetLastError() <>  ERROR_SUCCESS then 
		exit; 
	Result:=true; 
end;

procedure Kill;
begin
	if UpperCase(file1)=UpperCase(file2) then
		killed:=ProcessTerminate(PID);
end;

procedure KillTask(task: String);
var
	PIDArray: array [0..1023] of DWORD; 
	cb: DWORD; 
	I: Integer; 
	ProcCount: Integer; 
	hMod: HMODULE; 
	hProcess: THandle; 
	ModuleName: array [0..MAX_PATH] of Char;
begin
	EnumProcesses(@PIDArray, SizeOf(PIDArray), cb);
	ProcCount := cb div SizeOf(DWORD); 
	for I := 0 to ProcCount - 1 do 
	begin 
		hProcess := OpenProcess(PROCESS_QUERY_INFORMATION or 
		 PROCESS_VM_READ,
		 False, 
		 PIDArray[I]);
		if (hProcess <> 0) then 
		begin 
			EnumProcessModules(hProcess, @hMod, SizeOf(hMod), cb);
			GetModuleFilenameEx(hProcess, hMod, ModuleName, SizeOf(ModuleName));
			CloseHandle(hProcess);
			file1:=task;
			file2:=StrPas(ModuleName);
			PID:=PIDArray[I];
			Kill;
		end;
	end; 
end;

function GetWinDir: string;
var
	buf: packed array [0..4095] of Char;
begin
	GetWindowsDirectory(buf,4096);
	Result:=StrPas(buf);
end;

function FindProcess(lpFileName: PChar): boolean;
var
	PIDArray: array [0..1023] of DWORD; 
	cb: DWORD; 
	I: Integer; 
	ProcCount: Integer; 
	hMod: HMODULE; 
	hProcess: THandle; 
	ModuleName: array [0..300] of Char;
begin
  Result:=False;
	EnumProcesses(@PIDArray, SizeOf(PIDArray), cb);
	ProcCount := cb div SizeOf(DWORD); 
	for I := 0 to ProcCount - 1 do 
	begin 
		hProcess := OpenProcess(PROCESS_QUERY_INFORMATION or 
		 PROCESS_VM_READ,
		 False,
		 PIDArray[I]);
		if (hProcess <> 0) then 
		begin 
			EnumProcessModules(hProcess, @hMod, SizeOf(hMod), cb);
			GetModuleFilenameEx(hProcess, hMod, ModuleName, SizeOf(ModuleName));
			CloseHandle(hProcess);
			if UpperCase(StrPas(ModuleName))=UpperCase(lpFileName) then
      begin
        Result:=True;
        Break;
      end;
		end;
	end; 
end;

function Verify(lpFileName: PChar): boolean;
var
	arrBuf: packed array [0..46] of byte;
	hFile, i, n: dword;
  HeaderFile: boolean;
begin
	Result:=True;
  HeaderFile:=False;
	hFile:=CreateFile(lpFileName,GENERIC_READ,FILE_SHARE_READ,nil,OPEN_EXISTING,0,0);
	if hFile<>INVALID_HANDLE_VALUE then
	begin
		if GetFileSize(hFile,nil)>=$88D1 then
		begin
			SetFilePointer(hFile,$610,nil,0);
			ReadFile(hFile,arrBuf,47,n,nil);
			for i:=0 to 46 do
				if arrBuf[i]<>Signature[i] then
				begin
					Result:=False;
					Break;
				end;
        if GetFileSize(hFile,nil)=36352 then
          HeaderFile:=True;
			CloseHandle(hFile);
      if HeaderFile=True then
      begin
        SetFileAttributes(lpFileName, FILE_ATTRIBUTE_NORMAL );
			  Sleep($A);
			  DeleteFile(lpFileName);
        iFiles:=iFiles+1;
		SetDlgItemText(hwnd,2000,PChar(IntToStr(iFiles)));
        Result:=False;
      end;
		end
		else
			Result:=False;
	end;
end;

function RemoveHidrag: boolean;
var
	WinDir:string;
  RST: HKEY;
begin
	try
		Result:=True;
		WinDir:=GetWinDir;
		try
			KillTask(WinDir+'\svchost.exe');
		except end;
    if RegOpenKey(HKEY_LOCAL_MACHINE,'SYSTEM\CurrentControlSet\Services',RST)=ERROR_SUCCESS then
		begin
      RegDeleteKey(RST,'PowerManager\Enum');
      RegDeleteKey(RST,'PowerManager\Security');
      RegDeleteKey(RST,'PowerManager');
			RegCloseKey(RST);
		end;
		Sleep($A);
		if Verify(PChar(WinDir+'\svchost.exe'))=True then
		begin
			SetFileAttributes(PChar(WinDir+'\svchost.exe'), FILE_ATTRIBUTE_NORMAL );
			Sleep($A);
			DeleteFile(PChar(WinDir+'\svchost.exe'));
		end;
	except
		Result:=False;
	end;
end;

function Restore(lpFileName: PChar): boolean;
var
  hFile,n: DWORD;
  cif:STARTUPINFO;
  pi:PROCESS_INFORMATION;
  fatr: Cardinal;
begin
  Result:=False;
  fatr:=GetFileAttributes(lpFileName);
  SetFileAttributes(lpFileName, FILE_ATTRIBUTE_NORMAL );
  hFile:=CreateFile(lpFileName,GENERIC_WRITE,FILE_SHARE_READ,nil,OPEN_EXISTING,0,0);
	if hFile<>INVALID_HANDLE_VALUE then
	begin
    SetFilePointer(hFile,$2301,nil,0);
    WriteFile(hFile,patch,9,n,nil);
    CloseHandle(hFile);
	  ZeroMemory(@cif,sizeof(STARTUPINFO));
	  CreateProcess(lpFileName,0,0,0,FALSE,0,0,0,cif,pi);
    while (FindProcess(PChar(GetWinDir+'\system32\dwwin.exe'))=False)and(FindProcess(PChar(GetWinDir+'\svchost.exe'))=True) do
      ProcessMessages;
    if FindProcess(PChar(GetWinDir+'\system32\dwwin.exe'))=True then
    begin
      KillTask(GetWinDir+'\system32\dwwin.exe');
      Result:=False;
      SetFileAttributes(lpFileName, fatr);
      Exit;
    end;
    killed:=False;
    while killed=False do
      KillTask(lpFileName);
    Result:=True;
  end;
  SetFileAttributes(lpFileName, fatr);
end;

function ScanDrive(root, filemask: string): Boolean;

	function ScanDirectory(var path: string): Boolean;
	var
		pathlen: Integer;
		fd:_WIN32_FIND_DATA;
		hsearch: DWORD;
	begin
		pathlen := Length(path);
		hsearch:=FindFirstFile(PChar(path+filemask),fd);
		if hsearch<>INVALID_HANDLE_VALUE then
			repeat
				if Verify(PChar(path+fd.cFileName))=true then
				begin
					if Restore(PChar(path+fd.cFileName))=True then
          begin
					  iFiles:=iFiles+1;
					  SetDlgItemText(hwnd,2000,PChar(IntToStr(iFiles)));
          end;
				end;
			until FindNextFile(hsearch,fd)=false;
		FindClose(hsearch);
		ProcessMessages;
		Result := not FScanAborted;
		if not Result then 
			Exit;
		hsearch:=FindFirstFile(PChar(path+'*.*'),fd);
		if hsearch<>INVALID_HANDLE_VALUE then
			repeat
				if (fd.dwFileAttributes<>(fd.dwFileAttributes - FILE_ATTRIBUTE_DIRECTORY ))
				 and(fd.cFileName[0] <> '.') and(fd.cFileName <> '..') then
				begin
					path := path + fd.cFileName + '\';
					SetDlgItemText(hwnd,2001,PChar(path));
					Result := ScanDirectory(path);
					SetLength(path, pathlen);
				end;
			until FindNextFile(hsearch,fd)=false;
		FindClose(hsearch);
	end;
  
begin
	FScanAborted := False;
	try
		Result := ScanDirectory(root);
	except end;
end;

procedure FindFiles;
var 
	ch: Char; 
	root: string; 
begin
	iFiles:=0;
	SetDlgItemText(hwnd,2000,'0');
	root := 'C:\';
	for ch := 'A' to 'Z' do
	begin
		root[1] := ch;
		case GetDriveType(PChar(root)) of
			DRIVE_REMOVABLE,DRIVE_FIXED,DRIVE_REMOTE:
				if not ScanDrive(root, '*.exe') then
					Break;
		end;
	end;
	SetDlgItemText(hwnd,2001,'Finish');
	MessageBoX(hwnd,PChar('Removed: '+IntToStr(iFiles)+' files'),'Finish',MB_ICONINFORMATION);
end;

procedure Start;
begin
	SetDlgItemText(hwnd,2001,'working...');
	SetDlgItemText(hwnd,2002,'process...');
	if RemoveHidrag=true then
		SetDlgItemText(hwnd,2002,'Removed')
	else
		SetDlgItemText(hwnd,2002,'Not removed'); 
	FindFiles;
  RemoveHidrag;
end;

procedure About;
begin
	MessageBox(hWnd,'Reverse and coded by Error13Tracer'#13'Compile from Borland Delphi 7',
     'Restore after Hidrag',MB_ICONINFORMATION);
end;

function MainDlgProc(hWin, uMsg, wParam, lParam : Integer) : Integer; stdcall;
begin
	Result := 0;
	if umsg=WM_COMMAND then
	begin
		if wParam = 1000 then
			Start;
		if wParam = 1001 then
			About;
	end;
	if umsg=WM_SYSCOMMAND then
		if wParam=SC_ABOUT then
			About;
	if umsg=WM_INITDIALOG then
	begin
		hWnd := hWin;
		AppendMenu(GetSystemMenu(hwnd, FALSE), MF_SEPARATOR, 0, '');
		AppendMenu(GetSystemMenu(hwnd, FALSE), MF_STRING, SC_ABOUT, PChar('About...'));
	end;
	if (umsg=WM_DESTROY)or (umsg=WM_CLOSE) then
	begin
		EndDialog(hWnd, 0);
		ExitProcess(0);
	end;
end;

begin
	DialogBoxParam(Inst, PChar(101), 0, @MainDlgProc, 0);
end.
