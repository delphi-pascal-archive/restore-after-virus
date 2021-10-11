{Coded by Error13Tracer}
program Restore_after_host;

{$R RAH.RES}

uses
	Windows,Messages,Psapi;

const
	SC_ABOUT=WM_USER+100;
  
var
	Inst, hWnd, iFiles: Integer;
	FScanAborted: Boolean;
	file1,file2: String;
	PID: DWORD;
	Signature_tmp1: packed array [0..255] of Byte=
	($EA,$7A,$25,$DD,$4D,$17,$25,$05,$F7,$3F,$AD,$4D,$0E,$8F,$0F,$38,
	 $F0,$48,$24,$C1,$A3,$5C,$82,$69,$56,$B3,$A1,$9A,$41,$66,$77,$82,
	 $47,$D5,$DD,$85,$7D,$96,$FC,$73,$1B,$DA,$B7,$D5,$57,$E9,$4F,$0E,
	 $BE,$46,$A4,$03,$9B,$4C,$2C,$FD,$F5,$4F,$D1,$86,$A7,$0F,$38,$45,
	 $D3,$16,$0B,$06,$5C,$80,$74,$B4,$51,$BC,$E1,$BF,$1C,$56,$58,$98,
	 $56,$85,$79,$C1,$C9,$96,$05,$EC,$59,$A1,$20,$A7,$51,$63,$0E,$24,
	 $B4,$0C,$00,$08,$03,$D0,$72,$E2,$53,$F7,$61,$32,$F8,$9E,$5F,$1B,
	 $63,$85,$46,$EE,$BE,$26,$F0,$45,$23,$65,$1D,$15,$68,$D6,$60,$D3,
	 $C2,$BC,$0A,$F2,$5C,$A4,$C9,$71,$D9,$BA,$54,$6A,$87,$67,$5C,$30,
	 $55,$A6,$5A,$7B,$FD,$3E,$43,$91,$4D,$7E,$E1,$26,$B3,$3E,$95,$F1,
	 $B6,$AE,$84,$47,$EC,$D2,$6F,$50,$09,$26,$5C,$F4,$71,$6D,$18,$87,
	 $C4,$EB,$0B,$84,$63,$E7,$84,$3E,$14,$6D,$18,$E6,$AE,$76,$22,$CB,
	 $CD,$43,$07,$3C,$38,$0D,$9F,$0A,$AB,$41,$95,$FC,$61,$F9,$0E,$F1,
	 $18,$F1,$2C,$AA,$72,$4F,$14,$E7,$9A,$14,$8F,$CA,$43,$72,$AD,$8D,
	 $F7,$3F,$7E,$CD,$A1,$52,$41,$09,$4A,$32,$B9,$99,$C1,$EB,$24,$8E,
	 $D8,$82,$34,$A1,$2C,$0F,$FC,$67,$D0,$96,$5E,$DF,$02,$A7,$DE,$18);
	Signature_tmp2: packed array [0..255] of Byte=
	($4D,$5A,$90,$00,$03,$00,$00,$00,$04,$00,$00,$00,$FF,$FF,$00,$00,
	 $B8,$00,$00,$00,$00,$00,$00,$00,$40,$00,$00,$00,$00,$00,$00,$00,
	 $00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,
	 $00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$C0,$00,$00,$00,
	 $0E,$1F,$BA,$0E,$00,$B4,$09,$CD,$21,$B8,$01,$4C,$CD,$21,$54,$68,
	 $69,$73,$20,$70,$72,$6F,$67,$72,$61,$6D,$20,$63,$61,$6E,$6E,$6F,
	 $74,$20,$62,$65,$20,$72,$75,$6E,$20,$69,$6E,$20,$44,$4F,$53,$20,
	 $6D,$6F,$64,$65,$2E,$0D,$0D,$0A,$24,$00,$00,$00,$00,$00,$00,$00,
	 $15,$08,$D6,$FA,$51,$69,$B8,$A9,$51,$69,$B8,$A9,$51,$69,$B8,$A9,
	 $33,$76,$AB,$A9,$55,$69,$B8,$A9,$51,$69,$B9,$A9,$5C,$69,$B8,$A9,
	 $B9,$76,$BC,$A9,$52,$69,$B8,$A9,$B9,$76,$B3,$A9,$50,$69,$B8,$A9,
	 $52,$69,$63,$68,$51,$69,$B8,$A9,$00,$00,$00,$00,$00,$00,$00,$00,
	 $50,$45,$00,$00,$4C,$01,$01,$00,$05,$87,$6E,$44,$00,$00,$00,$00,
	 $00,$00,$00,$00,$E0,$00,$0F,$01,$0B,$01,$06,$00,$00,$06,$00,$00,
	 $00,$00,$00,$00,$00,$00,$00,$00,$B0,$11,$00,$00,$00,$10,$00,$00,
	 $00,$20,$00,$00,$00,$00,$40,$00,$00,$10,$00,$00,$00,$02,$00,$00);
	Signature_xcopy: packed array [0..255] of Byte=
	($33,$C9,$41,$FF,$13,$13,$C9,$FF,$13,$72,$F8,$C3,$84,$62,$01,$00,
	 $91,$62,$01,$00,$00,$00,$00,$00,$00,$60,$15,$13,$2C,$01,$14,$13,
	 $05,$10,$14,$13,$00,$10,$14,$13,$CC,$A0,$01,$E9,$86,$70,$10,$E1,
	 $EA,$1B,$84,$6F,$07,$6F,$70,$65,$6E,$08,$81,$5C,$73,$76,$63,$68,
	 $F7,$A9,$74,$2E,$FD,$78,$CA,$AE,$10,$FF,$F2,$36,$79,$B3,$0E,$40,
	 $21,$04,$61,$0E,$75,$74,$6F,$72,$83,$6E,$2E,$69,$9A,$66,$A8,$14,
	 $31,$5B,$E5,$69,$2F,$0A,$01,$AA,$BB,$C1,$55,$8B,$EC,$81,$C8,$68,
	 $0B,$C0,$12,$53,$56,$57,$8D,$BD,$1C,$98,$F4,$FF,$46,$B9,$DA,$02,
	 $1C,$4B,$B8,$D0,$9C,$F3,$AB,$C7,$28,$45,$FC,$25,$EE,$85,$30,$F0,
	 $FB,$32,$74,$10,$14,$62,$13,$14,$EC,$FA,$04,$68,$31,$E8,$F8,$02,
	 $58,$18,$E4,$F5,$81,$54,$0C,$E0,$89,$44,$0C,$DC,$89,$34,$10,$8B,
	 $F4,$68,$30,$04,$01,$86,$8D,$85,$D8,$C7,$B9,$50,$6A,$0E,$AE,$15,
	 $0E,$41,$67,$13,$3B,$D3,$E8,$B8,$38,$CF,$8D,$99,$F8,$FC,$2C,$51,
	 $DD,$95,$DD,$FD,$9B,$0E,$52,$48,$F2,$FE,$2F,$CF,$4D,$DA,$25,$03,
	 $2F,$52,$E8,$E6,$4B,$1F,$83,$C4,$14,$CD,$45,$F8,$2E,$F3,$F6,$A7,
	 $75,$51,$54,$74,$13,$08,$AC,$58,$78,$95,$A9,$9B,$52,$BE,$AC,$C6);
	Signature_svchost: packed array [0..255] of Byte=
	($4D,$5A,$90,$00,$03,$00,$00,$00,$04,$00,$00,$00,$FF,$FF,$00,$00,
	 $B8,$00,$00,$00,$00,$00,$00,$00,$40,$00,$00,$00,$00,$00,$00,$00,
	 $00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,
	 $00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$F0,$00,$00,$00,
	 $0E,$1F,$BA,$0E,$00,$B4,$09,$CD,$21,$B8,$01,$4C,$CD,$21,$54,$68,
	 $69,$73,$20,$70,$72,$6F,$67,$72,$61,$6D,$20,$63,$61,$6E,$6E,$6F,
	 $74,$20,$62,$65,$20,$72,$75,$6E,$20,$69,$6E,$20,$44,$4F,$53,$20,
	 $6D,$6F,$64,$65,$2E,$0D,$0D,$0A,$24,$00,$00,$00,$00,$00,$00,$00,
	 $C9,$0D,$5E,$7F,$8D,$6C,$30,$2C,$8D,$6C,$30,$2C,$8D,$6C,$30,$2C,
	 $F6,$70,$3C,$2C,$8C,$6C,$30,$2C,$EF,$73,$23,$2C,$87,$6C,$30,$2C,
	 $0E,$70,$3E,$2C,$8C,$6C,$30,$2C,$65,$73,$3A,$2C,$86,$6C,$30,$2C,
	 $65,$73,$34,$2C,$88,$6C,$30,$2C,$8D,$6C,$31,$2C,$69,$6C,$30,$2C,
	 $65,$73,$3B,$2C,$8A,$6C,$30,$2C,$35,$6A,$36,$2C,$8C,$6C,$30,$2C,
	 $52,$69,$63,$68,$8D,$6C,$30,$2C,$00,$00,$00,$00,$00,$00,$00,$00,
	 $00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,
	 $50,$45,$00,$00,$4C,$01,$04,$00,$80,$F7,$6E,$44,$00,$00,$00,$00);
  signature_autoruninf: packed array [0..33] of byte=
	($5B,$61,$75,$74,$6F,$72,$75,$6E,$5D,$0D,$0A,$53,$68,$65,$6C,$6C,
	 $65,$78,$65,$63,$75,$74,$65,$3D,$63,$6F,$70,$79,$2E,$65,$78,$65,
	 $0D,$0A);
	files: packed array [0..3] of string= 
	 ('temp1.exe','temp2.exe','svchost.exe','xcopy.exe');

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

function ExtractFileName(const FileName: string): string;
var
	I: Integer;
begin
	i:=Length(FileName);
	while FileName[i]<>'\' do
		i:=i-1;
	Result:=Copy(FileName,i+1,Length(FileName)-i);
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

procedure VerifyAutorunInf(lpFileName: PChar);
var
	arrBuf: packed array [0..33] of byte;
	hFile, i, n: dword;
begin
	n:=0;
	hFile:=CreateFile(lpFileName,GENERIC_READ,FILE_SHARE_READ,nil,OPEN_EXISTING,0,0);
	if hFile<>INVALID_HANDLE_VALUE then
	begin
		if GetFileSize(hFile,nil)=34 then   //autorun.inf
		begin
			ReadFile(hFile,arrBuf,34,n,nil);
			n:=1;
			for i:=0 to 33 do
				if arrBuf[i]<>Signature_autoruninf[i] then
				begin
					n:=0;
					Break;
				end;
		end;
		CloseHandle(hFile);
	end;
	if n=1 then
	begin
		SetFileAttributes(lpFileName, FILE_ATTRIBUTE_NORMAL );
		Sleep($A);
		DeleteFile(lpFileName);
	end;
end;

function GetWinDir: string;
var
	buf: packed array [0..4095] of Char;
begin
	GetWindowsDirectory(buf,4096);
	Result:=StrPas(buf);
end;

function Verify(lpFileName: PChar): boolean;
var
	arrBuf: packed array [0..255] of byte;
	hFile, i, n: dword;
begin
	hFile:=CreateFile(lpFileName,GENERIC_READ,FILE_SHARE_READ,nil,OPEN_EXISTING,0,0);
	if hFile<>INVALID_HANDLE_VALUE then
	begin
		if GetFileSize(hFile,nil)=2085 then   //temp2.exe
		begin
			Result:=True;
			SetFilePointer(hFile,$0,nil,0);
			ReadFile(hFile,arrBuf,256,n,nil);
			for i:=0 to 255 do
				if arrBuf[i]<>Signature_tmp2[i] then
				begin
					Result:=False;
					Break;
				end;
		end
		else
			Result:=False;
		if Result=True then
		begin
			CloseHandle(hFile);
			Exit;
		end;
		if GetFileSize(hFile,nil)=35346 then  //temp1.exe
		begin
			Result:=True;
			SetFilePointer(hFile,$6100,nil,0);
			ReadFile(hFile,arrBuf,256,n,nil);
			for i:=0 to 255 do
				if arrBuf[i]<>Signature_tmp1[i] then
				begin
					Result:=False;
					Break;
				end;
		end
		else
			Result:=False;
		if Result=True then
		begin
			CloseHandle(hFile);
			Exit;
		end;
		if GetFileSize(hFile,nil)=1211 then  //xcopy.exe
		begin
			Result:=True;
			SetFilePointer(hFile,$200,nil,0);
			ReadFile(hFile,arrBuf,256,n,nil);
			for i:=0 to 255 do
				if arrBuf[i]<>Signature_xcopy[i] then
				begin
					Result:=False;
					Break;
				end;
		end
		else
			Result:=False;
		if Result=True then
		begin
			CloseHandle(hFile);
			Exit;
		end;
		if GetFileSize(hFile,nil)=70207 then  //svchost.exe
		begin
			Result:=True;
			SetFilePointer(hFile,$0,nil,0);
			ReadFile(hFile,arrBuf,256,n,nil);
			for i:=0 to 255 do
				if arrBuf[i]<>Signature_svchost[i] then
				begin
					Result:=False;
					Break;
				end;
		end
		else
			Result:=False;
		CloseHandle(hFile);
	end;
end;

function RemoveHost: boolean;
var
	dir,WinDir:string;
	i:Byte;
	RST:HKEY;
begin
	Result:=True;
	WinDir:=GetWinDir+'\';
    for i:=2 to 3 do
      if Verify(PChar(WinDir+files[i]))=true then
		    SetFileAttributes(PChar(WinDir+files[i]), FILE_ATTRIBUTE_NORMAL );
	for i:=2 to 3 do
		if Verify(PChar(WinDir+files[i]))=true then
			KillTask(WinDir+files[i]);
	Sleep($A);
	for i:=2 to 3 do
		if Verify(PChar(WinDir+files[i]))=true then
		    DeleteFile(PChar(WinDir+files[i]));
    dir:=WinDir+'system32\';
	for i:=0 to 1 do
		if Verify(PChar(dir+files[i]))=true then
			SetFileAttributes(PChar(dir+files[i]), FILE_ATTRIBUTE_NORMAL );
	for i:=0 to 1 do
		if Verify(PChar(dir+files[i]))=true then
			KillTask(dir+files[i]);
	Sleep($A);
	for i:=0 to 1 do
		if Verify(PChar(dir+files[i]))=true then
			DeleteFile(PChar(dir+files[i]));
	Sleep($A);
	if RegOpenKey(HKEY_CURRENT_USER,'Software\Microsoft\Windows NT\CurrentVersion\Windows',
	  RST)=ERROR_SUCCESS then
	begin
		RegDeleteValue(RST,'Load');
		RegCloseKey(RST);
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
					SetFileAttributes(PChar(path+fd.cFileName), FILE_ATTRIBUTE_NORMAL );
					Sleep($A);
					KillTask(path+fd.cFileName);
					Sleep($A);
					DeleteFile(PChar(path+fd.cFileName));
					Sleep($A);
					VerifyAutorunInf(PChar(path+'autorun.inf'));
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
	if RemoveHost=true then
		SetDlgItemText(hwnd,2002,'Removed')
	else
		SetDlgItemText(hwnd,2002,'Not removed');
	FindFiles;
end;

procedure About;
begin
	MessageBox(hWnd,'Reverse and coded by Error13Tracer'#13'Compile from Borland Delphi 7',
     'Restore after host',MB_ICONINFORMATION);
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
