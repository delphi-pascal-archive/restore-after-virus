{Coded by Error13Tracer}
program Restore_after_brontok;

{$R RABC.RES}

uses
	Windows,Messages,Tlhelp32;

const
	SC_ABOUT=WM_USER+100;
  
var
	Inst, hWnd, iFiles: Integer;
	FScanAborted: Boolean;
	lpBuffer: packed array [0..255] of Char;
	Signature: packed array [0..255] of Byte=
	($00,$00,$00,$00,$44,$41,$51,$00,$46,$12,$D2,$C3,$00,$40,$02,$00,
	 $00,$10,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,
	 $00,$00,$00,$00,$00,$00,$00,$00,$E0,$00,$00,$C0,$02,$D2,$75,$DB,
	 $8A,$16,$EB,$D4,$00,$90,$01,$00,$00,$50,$02,$00,$BF,$A4,$00,$00,
	 $00,$02,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,$00,
	 $E0,$00,$00,$C0,$BE,$1C,$50,$42,$00,$8B,$DE,$AD,$AD,$50,$AD,$97,
	 $B2,$80,$A4,$B6,$80,$FF,$13,$73,$F9,$33,$C9,$FF,$13,$73,$16,$33,
	 $C0,$FF,$13,$73,$21,$B6,$80,$41,$B0,$10,$FF,$13,$12,$C0,$73,$FA,
	 $75,$3E,$AA,$EB,$E0,$E8,$76,$4E,$02,$00,$02,$F6,$83,$D9,$01,$75,
	 $0E,$FF,$53,$FC,$EB,$26,$AC,$D1,$E8,$74,$2F,$13,$C9,$EB,$1A,$91,
	 $48,$C1,$E0,$08,$AC,$FF,$53,$FC,$3D,$00,$7D,$00,$00,$73,$0A,$80,
	 $FC,$05,$73,$06,$83,$F8,$7F,$77,$02,$41,$41,$95,$8B,$C5,$B6,$00,
	 $56,$8B,$F7,$2B,$F0,$F3,$A4,$5E,$EB,$9B,$AD,$85,$C0,$75,$90,$E8,
	 $4E,$F5,$02,$00,$AD,$96,$AD,$97,$56,$AC,$3C,$00,$75,$FB,$FF,$53,
	 $F0,$95,$56,$AD,$0F,$C8,$40,$59,$74,$EC,$79,$07,$AC,$3C,$00,$75,
	 $FB,$91,$40,$50,$55,$FF,$53,$F4,$AB,$85,$C0,$75,$E5,$C3,$00,$00);
	Files:packed array [0..6] of string=('winlogon.exe','sempalong.exe',
	 'smss.exe','csrss.exe','inetinfo.exe','lsass.exe','services.exe');

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

function KillTask(ExeFileName: string): integer;
const
	PROCESS_TERMINATE=$0001;
var
	ContinueLoop: BOOL;
	FSnapshotHandle: THandle;
	FProcessEntry32: TProcessEntry32;
begin
	result := 0;
	FSnapshotHandle := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	FProcessEntry32.dwSize := Sizeof(FProcessEntry32);
	ContinueLoop := Process32First(FSnapshotHandle,FProcessEntry32);
	while integer(ContinueLoop) <> 0 do
	begin
		if ((UpperCase(ExtractFileName(FProcessEntry32.szExeFile)) =
		 UpperCase(ExeFileName)) or (UpperCase(FProcessEntry32.szExeFile) =
		 UpperCase(ExeFileName))) then  
			Result := Integer(TerminateProcess(OpenProcess(
			 PROCESS_TERMINATE, BOOL(0), FProcessEntry32.th32ProcessID), 0));
		ContinueLoop := Process32Next(FSnapshotHandle, FProcessEntry32);
	end;
	CloseHandle(FSnapshotHandle);
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

function GetWinDir: string;
var
	buf: packed array [0..4095] of Char;
begin
	GetWindowsDirectory(buf,4096);
	Result:=StrPas(buf);
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

function RemoveBrontok: boolean;
var
	dir,WinDir,HomePath:string;
	i:DWORD;
	RST:HKEY;
	SI:_STARTUPINFOA;
	PI:_PROCESS_INFORMATION;
begin
	try
		Result:=True;
		HomePath:=GetHomePath;
		WinDir:=GetWinDir;
		dir:=HomePath+'\Local Settings\Application Data\';
		if DirectoryExists(dir)=false then
			Result:=False;
		for i:=0 to 6 do
			SetFileAttributes(PChar(dir+files[i]), FILE_ATTRIBUTE_NORMAL );
		for i:=0 to 6 do
			KillTask(files[i]);
		Sleep($A);
		for i:=0 to 6 do
			SetFileAttributes(PChar(dir+files[i]), FILE_ATTRIBUTE_NORMAL );
		Sleep($A);
		for i:=0 to 6 do
			DeleteFile(PChar(dir+files[i]));
		DeleteFile(PChar(dir+'Kosong.Bron.Tok.txt'));
		DeleteFile(PChar(dir+'BronNetDomList.bat'));
		DeleteFile(PChar(HomePath+'\Шаблоны\Brengkolang.com'));
		DeleteFile(PChar(HomePath+'\Главное меню\Программы\Автозагрузка\Empty.pif'));
		Sleep($A);
		RemoveDirectory(PChar(dir+'Loc.Mail.Bron.Tok'));
		for i:=1 to 31 do
			RemoveDirectory(PChar(dir+'Bron.tok-12-'+IntToStr(i)));
		RemoveDirectory(PChar(dir+'Ok-SendMail-Bron-tok'));
		DeleteFile(PChar(WinDir+'\Tasks\At1.job'));
		SetFileAttributes(PChar(WinDir+'\explorasi.exe'), FILE_ATTRIBUTE_NORMAL );
		DeleteFile(PChar(WinDir+'\eksplorasi.exe'));
		SetFileAttributes(PChar(WinDir+'\ShellNew\'+files[1]), FILE_ATTRIBUTE_NORMAL );
		DeleteFile(PChar(WinDir+'\ShellNew\'+files[1]));
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
		KillTask('explorer.exe');
		Sleep($A);
		CreateProcess(nil, PChar(WInDir+'\explorer.exe'), nil, nil, False, NORMAL_PRIORITY_CLASS,
		 nil, nil, SI, PI);
		if RegOpenKey(HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
		 RST)=ERROR_SUCCESS then
		begin
			RegDeleteValue(RST,'Shell');
			RegCloseKey(RST);
		end;
		if RegOpenKey(HKEY_LOCAL_MACHINE,'Software\Microsoft\Windows\CurrentVersion\Run',RST)=ERROR_SUCCESS then
		begin
			RegDeleteValue(RST,'Bron-Spizaetus');
			RegCloseKey(RST);
		end;
		if RegOpenKey(HKEY_CURRENT_USER,'Software\Microsoft\Windows\CurrentVersion\Run',RST)=ERROR_SUCCESS then
		begin
			RegDeleteValue(RST,'Tok-Cirrhatus');
			RegCloseKey(RST);
		end;
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
		if GetFileSize(hFile,nil)=42687 then
		begin
			SetFilePointer(hFile,$100,nil,0);
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
     'Restore after brontok',MB_ICONINFORMATION);
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
