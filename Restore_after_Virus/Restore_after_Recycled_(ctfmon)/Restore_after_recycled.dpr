{Coded by Error13Tracer}
program Restore_after_recycled;

{$R RARD.RES}

uses
	Windows,Messages,Psapi;

const
	SC_ABOUT=WM_USER+100;
  
var
	Inst, hWnd, iFiles: Integer;
	FScanAborted: Boolean;
	lpBuffer: packed array [0..255] of Char;
	file1,file2: String;
	PID: DWORD;
	Signature_ctfmon: packed array [0..255] of Byte=
	($4D,$5A,$90,$00,$03,$00,$00,$00,$04,$00,$00,$00,$FF,$FF,$00,$00,
	 $B8,$00,$00,$00,$00,$00,$00,$00,$40,$00,$00,$00,$00,$00,$00,$00,
	 $00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,
	 $00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$B0,$00,$00,$00,
	 $0E,$1F,$BA,$0E,$00,$B4,$09,$CD,$21,$B8,$01,$4C,$CD,$21,$54,$68,
	 $69,$73,$20,$70,$72,$6F,$67,$72,$61,$6D,$20,$63,$61,$6E,$6E,$6F,
	 $74,$20,$62,$65,$20,$72,$75,$6E,$20,$69,$6E,$20,$44,$4F,$53,$20,
	 $6D,$6F,$64,$65,$2E,$0D,$0D,$0A,$24,$00,$00,$00,$00,$00,$00,$00,
	 $C9,$E1,$07,$DB,$8D,$80,$69,$88,$8D,$80,$69,$88,$8D,$80,$69,$88,
	 $BB,$A6,$64,$88,$8C,$80,$69,$88,$52,$69,$63,$68,$8D,$80,$69,$88,
	 $00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,
	 $50,$45,$00,$00,$4C,$01,$03,$00,$EC,$CE,$A0,$44,$00,$00,$00,$00,
	 $00,$00,$00,$00,$E0,$00,$0F,$01,$0B,$01,$06,$00,$00,$30,$00,$00,
	 $00,$20,$00,$00,$00,$00,$00,$00,$9C,$10,$00,$00,$00,$10,$00,$00,
	 $00,$40,$00,$00,$00,$00,$40,$00,$00,$10,$00,$00,$00,$10,$00,$00,
	 $04,$00,$00,$00,$33,$00,$34,$08,$04,$00,$00,$00,$00,$00,$00,$00);
	Signature_INFO2: packed array [0..21] of byte=
	($05,$20,$20,$20,$20,$20,$20,$20,$06,$20,$20,$20,$20,$03,$20,$20,
	 $20,$20,$20,$20,$0D,$0A);
	Signature_DesktopIni: packed array [0..64] of byte=
	($5B,$2E,$53,$68,$65,$6C,$6C,$43,$6C,$61,$73,$73,$49,$6E,$66,$6F,
	 $5D,$0D,$0A,$43,$4C,$53,$49,$44,$3D,$7B,$36,$34,$35,$46,$46,$30,
	 $34,$30,$2D,$35,$30,$38,$31,$2D,$31,$30,$31,$42,$2D,$39,$46,$30,
	 $38,$2D,$30,$30,$41,$41,$30,$30,$32,$46,$39,$35,$34,$45,$7D,$0D,
	 $0A);
	Files:packed array [0..3] of string=
	('ctfmon.exe','INFO2','desktop.ini','autorun.inf');

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

function DirectoryExists(S: String):boolean;
var
	fd:_WIN32_FIND_DATA;
	hsearch: DWORD;
begin
	Result:=false;
	if S[Length(S)]='\' then
		Delete(S,Length(S),1);
	if (Length(S)=2)and(S[2]=':') then
	begin
		hsearch:=GetDriveType(PChar(S+'\'));
		case hsearch of
			DRIVE_REMOVABLE,DRIVE_FIXED,DRIVE_REMOTE,DRIVE_CDROM:
			begin
				Result:=true;
				Exit;
			end;
			else
				Exit;
		end;
	end;
	hsearch:=FindFirstFile(PChar(S),fd);
	if hsearch<>INVALID_HANDLE_VALUE then
	begin
		if (fd.dwFileAttributes=(FILE_ATTRIBUTE_DIRECTORY or fd.dwFileAttributes)) then
			Result:=true;
		FindClose(hsearch);
	end;
end;

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

function GetHomePath: String;

	function GetRegValue(value: PChar): boolean;
	var
		Key: HKEY;
		dwType: DWord;
		dwLength: DWord;
	begin
		if RegOpenKey(HKEY_CURRENT_USER,'Volatile Environment',Key)=ERROR_SUCCESS then 
		begin
			dwType:=RegQueryValueEx(Key, value, nil, @dwType, @lpBuffer, @dwLength); //No Remove (Not Work!!!)
			if (RegQueryValueEx(Key, value, nil, @dwType, @lpBuffer, @dwLength) <> ERROR_SUCCESS)and
			 (dwType = REG_SZ) then
				Result:=false
			else
				Result:=true;
			RegCloseKey(Key);
		end;
	end;

begin
	if GetRegValue('HOMEDRIVE')=True then
	begin
		Result:=StrPas(lpBuffer);
		if GetRegValue('HOMEPATH')=True then
		 	Result:=Result+StrPas(lpBuffer)
		else
			Result:='';
	end
	else
		Result:='';
end;

function RemoveRecycled: boolean;
var
	dir:string;
begin
	try
		Result:=True;
		dir:=GetHomePath+'\Главное меню\Программы\Автозагрузка\';
		if DirectoryExists(dir)=false then
		begin
			Result:=False;
			Exit;
		end;
		SetFileAttributes(PChar(dir+files[0]), FILE_ATTRIBUTE_NORMAL );
		Sleep($A);
		KillTask(dir+files[0]);
		Sleep($A);
		DeleteFile(PChar(dir+files[0]));
	except
		Result:=False;
	end;
end;

function VerifyAndDelete(lpPath: PChar): boolean;
var
	arrBuf: packed array [0..64] of byte;
	hFile, i: dword;
	yes,yes1: boolean;
	fname: PChar;
begin
	yes:=False;
	fname:=PChar(lpPath+files[1]);
	hFile:=CreateFile(fname,GENERIC_READ,FILE_SHARE_READ,nil,OPEN_EXISTING,0,0);
	if hFile<>INVALID_HANDLE_VALUE then
	begin
		if GetFileSize(hFile,nil)=22 then
		begin
			yes:=True;
			SetFilePointer(hFile,$0,nil,0);
			ReadFile(hFile,arrBuf,22,i,nil);
			for i:=0 to 21 do
				if arrBuf[i]<>Signature_INFO2[i] then
				begin
					yes:=False;
					Break;
				end;
		end
		else
			yes:=False;
		CloseHandle(hFile);
	end;
	if yes=true then
	begin
		SetFileAttributes(fname, FILE_ATTRIBUTE_NORMAL );
		Sleep($A);
		DeleteFile(fname);
	end;
	yes1:=False;
	fname:=PChar(lpPath+files[2]);
	hFile:=CreateFile(fname,GENERIC_READ,FILE_SHARE_READ,nil,OPEN_EXISTING,0,0);
	if hFile<>INVALID_HANDLE_VALUE then
	begin
		if GetFileSize(hFile,nil)=65 then
		begin
			yes1:=True;
			SetFilePointer(hFile,$0,nil,0);
			ReadFile(hFile,arrBuf,65,i,nil);
			for i:=0 to 64 do
				if arrBuf[i]<>Signature_desktopIni[i] then
				begin
					yes1:=False;
					Break;
				end;
		end
		else
			yes1:=False;
		CloseHandle(hFile);
	end;
	if yes1=true then
	begin
		SetFileAttributes(fname, FILE_ATTRIBUTE_NORMAL );
		Sleep($A);
		DeleteFile(fname);
	end;
	if (yes=True)or(yes1=True) then
		Result:=True
	else
		Result:=False;
end;

function Verify(lpFileName: PChar): boolean;
var
	arrBuf: packed array [0..255] of byte;
	hFile, i: dword;
begin
	Result:=True;
	hFile:=CreateFile(lpFileName,GENERIC_READ,FILE_SHARE_READ,nil,OPEN_EXISTING,0,0);
	if hFile<>INVALID_HANDLE_VALUE then
	begin
		if GetFileSize(hFile,nil)=20480 then
		begin
			SetFilePointer(hFile,$0,nil,0);
			ReadFile(hFile,arrBuf,256,i,nil);
			for i:=0 to 255 do
				if arrBuf[i]<>Signature_ctfmon[i] then
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

function RecycledDir(path: String): boolean;
var
	i: Integer;
begin
	Delete(path,Length(path),1);
	i:=Length(path);
	while (i>=1)and(path[i]<>'\') do
		i:=i-1;
	path:=Copy(path,i+1,Length(path)-i);
	if path='Recycled' then
		Result:=True
	else
		Result:=False;
end;

procedure RemoveAutorun(path: String; goback: boolean);
var
	Dir,Buf: String;
	i: Integer;
	F: TextFile;
begin
	Dir:=Path;
	Delete(Dir,Length(Dir),1);
	i:=Length(Dir);
	while (i>=1)and(Dir[i]<>'\') do
		i:=i-1;
	Dir:=Copy(Dir,1,i);
	path:=Copy(path,i+1,Length(path)-i);
	if goback=True then
		path:=path+path;
	if DirectoryExists(Dir)=False then
		Exit;
	try
		AssignFile(f,Dir+Files[3]);
		Reset(F);
		ReadLn(F,Buf);
		if Buf<>'[autorun]'then
		begin
			CloseFile(F);
			Exit;
		end;
		ReadLn(F,Buf);
		if Buf<>'shellexecute='+path+Files[0] then
		begin
			CloseFile(F);
			Exit;
		end;
		CloseFile(F);
		SetFileAttributes(PChar(Dir+Files[3]), FILE_ATTRIBUTE_NORMAL );
		Sleep($A);
		DeleteFile(PChar(Dir+Files[3]));
	except end;
end;

function ScanDrive(root, filemask: string): Boolean;

	function ScanDirectory(var path: string): Boolean;
	var
		pathlen: Integer;
		fd:_WIN32_FIND_DATA;
		hsearch: DWORD;
		removedir: boolean;
		gotoback: boolean;
	begin
		pathlen := Length(path);
		removedir:=False;
		gotoback:=False;
		hsearch:=FindFirstFile(PChar(path+filemask),fd);
		if hsearch<>INVALID_HANDLE_VALUE then
			repeat
				if Verify(PChar(path+fd.cFileName))=true then
				begin
					SetFileAttributes(PChar(path+fd.cFileName), FILE_ATTRIBUTE_NORMAL );
					Sleep($A);
					DeleteFile(PChar(path+fd.cFileName));
					if RecycledDir(path)=True then
						gotoback:=True;
					if VerifyAndDelete(PChar(path))=True then
						removedir:=True;
					iFiles:=iFiles+1;
					SetDlgItemText(hwnd,2000,PChar(IntToStr(iFiles)));
				end;
			until FindNextFile(hsearch,fd)=false;
		FindClose(hsearch);
		if removedir=true then
		begin
			SetFileAttributes(PChar(path), FILE_ATTRIBUTE_NORMAL);
			Sleep($A);
			RemoveDirectory(PChar(path));
			RemoveAutorun(path,false);
		end;
		if gotoback=true then
		begin
			file1:=path;
			Delete(file1,Length(file1)-9,9);
			if VerifyAndDelete(PChar(file1))=True then
			begin
				SetFileAttributes(PChar(file1), FILE_ATTRIBUTE_NORMAL);
				RemoveAutorun(file1,true);
			end;
		end;
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
	if RemoveRecycled=true then
		SetDlgItemText(hwnd,2002,'Removed')
	else
		SetDlgItemText(hwnd,2002,'Not removed');
	FindFiles;
end;

procedure About;
begin
	MessageBox(hWnd,'Reverse and coded by Error13Tracer'#13'Compile from Borland Delphi 7',
     'Restore after Recycled(ctfmon)',MB_ICONINFORMATION);
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
