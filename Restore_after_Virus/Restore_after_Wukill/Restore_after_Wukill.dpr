{Coded by Error13Tracer}
program Restore_after_Wukill;

{$R RAWK.RES}

uses
	Windows,Messages,TlHelp32,Psapi;

const
	SC_ABOUT=WM_USER+100;
  
var
	Inst, hWnd, iFiles: Integer;
	FScanAborted: Boolean;
	file1,file2: String;
	PID: DWORD;
	Signature: packed array [0..255] of Byte=
	($EC,$20,$40,$00,$00,$00,$04,$00,$10,$95,$40,$00,$00,$00,$00,$00,
	 $00,$00,$00,$00,$A1,$18,$95,$40,$00,$0B,$C0,$74,$02,$FF,$E0,$68,
	 $FC,$20,$40,$00,$B8,$80,$10,$40,$00,$FF,$D0,$FF,$E0,$00,$00,$00,
	 $0C,$00,$00,$00,$52,$65,$67,$43,$6C,$6F,$73,$65,$4B,$65,$79,$00,
	 $D8,$20,$40,$00,$34,$21,$40,$00,$00,$00,$04,$00,$1C,$95,$40,$00,
	 $00,$00,$00,$00,$00,$00,$00,$00,$A1,$24,$95,$40,$00,$0B,$C0,$74,
	 $02,$FF,$E0,$68,$40,$21,$40,$00,$B8,$80,$10,$40,$00,$FF,$D0,$FF,
	 $E0,$00,$00,$00,$0E,$00,$00,$00,$52,$65,$67,$43,$72,$65,$61,$74,
	 $65,$4B,$65,$79,$41,$00,$00,$00,$D8,$20,$40,$00,$78,$21,$40,$00,
	 $00,$00,$04,$00,$28,$95,$40,$00,$00,$00,$00,$00,$00,$00,$00,$00,
	 $A1,$30,$95,$40,$00,$0B,$C0,$74,$02,$FF,$E0,$68,$88,$21,$40,$00,
	 $B8,$80,$10,$40,$00,$FF,$D0,$FF,$E0,$00,$00,$00,$0E,$00,$00,$00,
	 $52,$65,$67,$44,$65,$6C,$65,$74,$65,$4B,$65,$79,$41,$00,$00,$00,
	 $D8,$20,$40,$00,$C0,$21,$40,$00,$00,$00,$04,$00,$34,$95,$40,$00,
	 $00,$00,$00,$00,$00,$00,$00,$00,$A1,$3C,$95,$40,$00,$0B,$C0,$74,
	 $02,$FF,$E0,$68,$D0,$21,$40,$00,$B8,$80,$10,$40,$00,$FF,$D0,$FF);
	Signature_CH: packed array [0..255] of Byte=
	($3C,$62,$6F,$64,$79,$3E,$3C,$68,$74,$6D,$6C,$3E,$0D,$0A,$3C,$62,
	 $6F,$64,$79,$20,$3E,$0D,$0A,$3C,$73,$63,$72,$69,$70,$74,$20,$6C,
	 $61,$6E,$67,$75,$61,$67,$65,$3D,$76,$62,$73,$63,$72,$69,$70,$74,
	 $3E,$0D,$0A,$64,$6F,$63,$75,$6D,$65,$6E,$74,$2E,$77,$72,$69,$74,
	 $65,$20,$22,$3C,$64,$69,$76,$20,$73,$74,$79,$6C,$65,$3D,$27,$70,
	 $6F,$73,$69,$74,$69,$6F,$6E,$3A,$61,$62,$73,$6F,$6C,$75,$74,$65,
	 $3B,$20,$6C,$65,$66,$74,$3A,$30,$70,$78,$3B,$20,$74,$6F,$70,$3A,
	 $30,$70,$78,$3B,$20,$77,$69,$64,$74,$68,$3A,$30,$70,$78,$3B,$20,
	 $68,$65,$69,$67,$68,$74,$3A,$30,$70,$78,$3B,$20,$7A,$2D,$69,$6E,
	 $64,$65,$78,$3A,$32,$38,$3B,$20,$76,$69,$73,$69,$62,$69,$6C,$69,
	 $74,$79,$3A,$20,$68,$69,$64,$64,$65,$6E,$27,$3E,$3C,$41,$50,$50,
	 $4C,$45,$54,$20,$4E,$41,$4D,$45,$3D,$4C,$48,$57,$20,$48,$45,$49,
	 $47,$48,$54,$3D,$30,$20,$57,$49,$44,$54,$48,$3D,$30,$20,$63,$6F,
	 $64,$65,$3D,$63,$6F,$6D,$2E,$6D,$73,$2E,$61,$63,$74,$69,$76,$65,
	 $58,$2E,$41,$63,$74,$69,$76,$65,$58,$43,$6F,$6D,$70,$6F,$6E,$65,
	 $6E,$74,$3E,$3C,$2F,$41,$50,$50,$4C,$45,$54,$3E,$3C,$2F,$64,$69);

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

function ExtractFileName(const FileName: string): string;
var
	I: Integer;
begin
	i:=Length(FileName);
	while (FileName[i]<>'\')and(I>0) do
		i:=i-1;
	Result:=Copy(FileName,i+1,Length(FileName)-i);
end;

function StrPas(lpString: array of Char): String;
var
	i: DWORD;
begin
	Result:='';
	for i:=0 to 4096 do
		if lpString[i]<>#0 then
			Result:=Result+lpString[i]
		else
			break;
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

function VerifyHHT(lpFileName: PChar): boolean;
var
	arrBuf: packed array [0..255] of byte;
	hFile, i, n: dword;
begin
	Result:=True;
	hFile:=CreateFile(lpFileName,GENERIC_READ,FILE_SHARE_READ,nil,OPEN_EXISTING,0,0);
	if hFile<>INVALID_HANDLE_VALUE then
	begin
		if GetFileSize(hFile,nil)=697 then
		begin
			ReadFile(hFile,arrBuf,256,n,nil);
			for i:=0 to 255 do
				if arrBuf[i]<>Signature_CH[i] then
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
		begin
			CloseHandle(hFile);
			Result:=False;
		end;
	end
  else
    Result:=False;
end;

function VerifyEXE(lpFileName: PChar): boolean;
var
	arrBuf: packed array [0..255] of byte;
	hFile, i, n: dword;
begin
	Result:=True;
	hFile:=CreateFile(lpFileName,GENERIC_READ,FILE_SHARE_READ,nil,OPEN_EXISTING,0,0);
	if hFile<>INVALID_HANDLE_VALUE then
	begin
		if GetFileSize(hFile,nil)=65024 then
		begin
			SetFilePointer(hFile,$2100,nil,0);
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
		begin
			CloseHandle(hFile);
			Result:=False;
		end;
	end
  else
    Result:=False;
end;

function FindInfectedProcess: boolean;
var
	cb: DWORD;
	I: Integer; 
	ProcCount: Integer; 
	hMod: HMODULE;
	hProcess: THandle;
	ModuleName: packed array [0..300] of Char;
	PIDArray: packed array [0..1023] of DWORD;
begin
	Result:= False;
	EnumProcesses(@PIDArray, SizeOf(PIDArray), cb);
	ProcCount := cb div SizeOf(DWORD); 
	for I := 0 to ProcCount - 1 do 
	begin 
		hProcess := OpenProcess(PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,False,PIDArray[I]);
		if (hProcess <> 0) then 
		begin 
			EnumProcessModules(hProcess, @hMod, SizeOf(hMod), cb);
			GetModuleFilenameEx(hProcess, hMod, ModuleName, SizeOf(ModuleName));
			CloseHandle(hProcess);
			if VerifyEXE(ModuleName)= True then
			begin
				Result:=True;
				try
					KillTask(ExtractFileName(ModuleName));
				except end;
			end;
		end;
	end; 
end;

function RemoveRegistryKeys: boolean;
var
	KEY: HKey;
	Buffer, lpBuffer: packed array [0..1023] of Char;
	Err, index: longint;
	dwSize: DWORD;
	dwType: DWORD;
	dwLength: DWORD;
begin
	Result:=False;
	Err := RegOpenKeyEx(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',0,KEY_ALL_ACCESS,KEY);
	if Err <> ERROR_SUCCESS then
		exit;
	index := 0;
	dwSize:=1024;
	dwLength:=1024;
	Err := RegEnumValue(KEY, index, Buffer, dwSize,0,@dwType, @lpBuffer, @dwLength);
	while err = ERROR_SUCCESS do
	begin
		if VerifyEXE(lpBuffer)=True then
		begin
			RegDeleteValue(KEY,Buffer);
			Result:=True;
		end
		else
			index:=index+1;
		dwLength:=1024;
		dwSize:=1024;
		Err := RegEnumValue(KEY, index, Buffer, dwSize,0,@dwType, @lpBuffer, @dwLength);
	end;
	RegCloseKey(KEY);
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
				if VerifyExe(PChar(path+fd.cFileName))=true then
				begin
					DeleteFile(PChar(path+fd.cFileName));
					iFiles:=iFiles+1;
					SetDlgItemText(hwnd,2000,PChar(IntToStr(iFiles)));
				end;
				if VerifyHHT (PChar(path+fd.cFileName))=True then
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
			DRIVE_REMOVABLE,DRIVE_FIXED,DRIVE_REMOTE:
				if not ScanDrive(root, '*.*') then
					Break;
		end;
	end;
	SetDlgItemText(hwnd,2001,'Finish');
	MessageBox(hwnd,PChar('Removed: '+IntToStr(iFiles)+' files'),'Finish',MB_ICONINFORMATION);
end;

procedure Start;
begin
	SetDlgItemText(hwnd,2001,'working...');
	SetDlgItemText(hwnd,2002,'process...');
	if FindInfectedProcess=True then
		SetDlgItemText(hwnd,2002,'Removed')
	else
		SetDlgItemText(hwnd,2002,'Not removed');
	if RemoveRegistryKeys=True then
		SetDlgItemText(hwnd,2002,'Removed')
	else
		SetDlgItemText(hwnd,2002,'Not removed');
	FindFiles;
end;

procedure About;
begin
	MessageBox(hWnd,'Reverse and coded by Error13Tracer'#13'Compile from Borland Delphi 7',
     'Restore after Wukill',MB_ICONINFORMATION);
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
