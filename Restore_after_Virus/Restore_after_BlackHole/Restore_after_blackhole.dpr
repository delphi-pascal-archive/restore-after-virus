{Coded by Error13Tracer}
program Restore_after_blackhole;

{$R RABC.RES}

uses
	Windows,Messages,Psapi;

const
	SC_ABOUT=WM_USER+100;
  
var
	Inst, hWnd, iFiles: Integer;
	FScanAborted: Boolean;
	file1,file2: String;
	PID: DWORD;
	Signature: packed array [0..255] of Byte=
	($3A,$7D,$02,$36,$89,$FB,$36,$A8,$EE,$11,$32,$CB,$91,$48,$16,$98,
	 $76,$04,$C8,$29,$7A,$A6,$89,$7D,$25,$84,$25,$6C,$DA,$77,$C6,$8D,
	 $7F,$0A,$FF,$15,$18,$E0,$12,$09,$01,$C3,$B9,$CC,$04,$5F,$07,$16,
	 $0C,$B6,$2F,$1C,$75,$BD,$01,$FF,$E4,$02,$8B,$08,$85,$C9,$74,$32,
	 $F6,$18,$50,$89,$C8,$CE,$C6,$BE,$A7,$40,$20,$59,$72,$19,$89,$47,
	 $FE,$31,$5E,$F3,$C2,$6E,$73,$EB,$A3,$62,$10,$D0,$D5,$2C,$3A,$C4,
	 $F9,$63,$E7,$2E,$E0,$DE,$0D,$04,$07,$DB,$FF,$1B,$52,$AC,$03,$5A,
	 $FF,$D1,$48,$8A,$80,$39,$26,$1A,$79,$0B,$62,$46,$FF,$FF,$CF,$F5,
	 $28,$8B,$80,$04,$2B,$23,$64,$CB,$CC,$C8,$C9,$D7,$CF,$C8,$CD,$CE,
	 $DB,$D8,$CA,$D9,$DA,$DC,$DD,$DE,$29,$BF,$9F,$FE,$DF,$E0,$E1,$E3,
	 $00,$E4,$E5,$AE,$50,$52,$51,$5B,$83,$B8,$BE,$6E,$79,$B0,$BA,$5A,
	 $58,$62,$31,$C0,$C7,$50,$97,$8F,$DF,$EE,$9F,$5B,$1F,$1D,$31,$D2,
	 $8B,$88,$21,$89,$90,$0B,$C8,$81,$DF,$5E,$71,$8E,$94,$89,$C6,$89,
	 $D7,$14,$39,$F7,$77,$13,$74,$2F,$7F,$33,$FC,$DF,$50,$78,$2A,$F3,
	 $A5,$89,$C1,$83,$E1,$03,$F3,$A4,$60,$72,$74,$0E,$FC,$8D,$7C,$0F,
	 $FC,$B8,$A6,$DA,$76,$31,$11,$FD,$33,$94,$04,$C7,$3E,$51,$A8,$AB);

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
	i:DWord;
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
		ProcessTerminate(PID);
end;

procedure KillTask(task: String);
var
	PIDArray: array [0..1023] of DWORD; 
	cb: DWORD; 
	I: Integer; 
	ProcCount: Integer; 
	hMod: HMODULE; 
	hProcess: THandle; 
	ModuleName: array [0..300] of Char;
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

function RemoveBrontok: boolean;
var
	WinDir:string;
	i:DWORD;
	RST:HKEY;
	SI:_STARTUPINFOA;
	PI:_PROCESS_INFORMATION;
begin
	try
		Result:=True;
		WinDir:=GetWinDir;
		KillTask(WinDir+'\Cursors\services.exe');
		Sleep($A);
		SetFileAttributes(PChar(WinDir+'\Cursors\services.exe'), FILE_ATTRIBUTE_NORMAL );
		Sleep($A);
		DeleteFile(PChar(WinDir+'\Cursors\services.exe'));
		if RegOpenKey(HKEY_LOCAL_MACHINE,'Software\Microsoft\Windows\CurrentVersion\Run',RST)=ERROR_SUCCESS then
		begin
			RegDeleteValue(RST,'Service');
			RegCloseKey(RST);
		end;
		i:=$0;
		if RegOpenKey(HKEY_CURRENT_USER,'Software\Microsoft\Windows\CurrentVersion\Policies\System',
		 RST)=ERROR_SUCCESS then
		begin
			RegSetValueEx(RST,'DisableRegistryTools',0,REG_DWORD,@i,4);
			RegCloseKey(RST);
		end;
		i:=$0;
		if RegOpenKey(HKEY_CURRENT_USER,'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer',
		 RST)=ERROR_SUCCESS then
		begin
			RegSetValueEx(RST,'NoFolderOptions',0,REG_DWORD,@i,4);
			RegCloseKey(RST);
		end;
		KillTask(WinDir+'\explorer.exe');
		Sleep($A);
		CreateProcess(nil, PChar(WinDir+'\explorer.exe'), nil, nil, False, NORMAL_PRIORITY_CLASS,
		 nil, nil, SI, PI);
	except
		Result:=False;
	end;
end;

function Verify(lpFileName: PChar): boolean;
var
	arrBuf: packed array [0..255] of byte;
	hFile, i, n: dword;
begin
	Result:=True;
	hFile:=CreateFile(lpFileName,GENERIC_READ,FILE_SHARE_READ,nil,OPEN_EXISTING,0,0);
	if hFile<>INVALID_HANDLE_VALUE then
	begin
		if GetFileSize(hFile,nil)=53326 then
		begin
			SetFilePointer(hFile,$1010,nil,0);
			ReadFile(hFile,arrBuf,256,n,nil);
			for i:=0 to 255 do
				if arrBuf[i]<>Signature[i] then
				begin
					Result:=False;
					Break;
				end;
			if Result=False then
			begin
				CloseHandle(hFile);
				Exit;
			end;
			CloseHandle(hFile);
		end
		else
			Result:=False;
	end;
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
					DeleteFile(PChar(path+fd.cFileName));
					iFiles:=iFiles+1;
					SetDlgItemText(hwnd,2000,PChar(IntToStr(iFiles)));
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
			DRIVE_REMOVABLE,DRIVE_FIXED,DRIVE_REMOTE,DRIVE_CDROM:
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
	if RemoveBrontok=true then
		SetDlgItemText(hwnd,2002,'Removed')
	else
		SetDlgItemText(hwnd,2002,'Not removed');
	FindFiles;
end;

procedure About;
begin
	MessageBox(hWnd,'Reverse and coded by Error13Tracer'#13'Compile from Borland Delphi 7',
     'Restore after BlackHole',MB_ICONINFORMATION);
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
