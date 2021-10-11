{Coded by Error13Tracer}
program Restore_after_AutorunVBS;

uses
	Windows,Tlhelp32;

const
	ProgramName='Restore after AutorunVBS';

var
	iFiles: Integer;
	Files: packed array [0..6] of PChar=('AUTORUN.VBS','AUTORUN.BAT',
	 'AUTORUN.TXT','AUTORUN.INF','AUTORUN.REG','AUTORUN.BIN','AUTORUN.FCB');

function IntToStr(Value: LongWord): string;
begin
	Str(Value, Result);
end;

function ExtractFileName(const FileName: string): string;
var
	I: Integer;
begin
	i:=Length(FileName);
	while (FileName[i]<>'\')and(i>0) do
		i:=i-1;
	Result:=Copy(FileName,i+1,Length(FileName)-i);
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

function SysDir: string;
var
	buf: packed array [0..4095] of Char;
begin
	GetWindowsDirectory(buf,4096);
	Result:=StrPas(buf);
	Result:=buf+'\system32\';
end;

function GetRegValue(value: PChar; var lpBuffer:  array of Char): boolean;
var
	Key: HKEY;
	dwType: DWord;
	dwLength: DWord;
begin
	Result:=false;
	if RegOpenKey(HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',Key)=ERROR_SUCCESS then
	begin
		if (RegQueryValueEx(Key, value, nil, @dwType, @lpBuffer, @dwLength) <> ERROR_SUCCESS)and
		 (dwType = REG_SZ) then
			Result:=false
		else
			Result:=true;
		RegCloseKey(Key);
	end;
end;

function WinDir: string;
var
	buf: packed array [0..4095] of Char;
begin
	GetWindowsDirectory(buf,4096);
	Result:=StrPas(buf);
end;

procedure RemoveAutorunVBS;
var
	lpBuffer: packed array [0..255] of Char;
	userinit: String;
	RST:HKEY;
	i: DWORD;
begin
	KillTask('WScript.exe');
	i:=$1;
	if RegOpenKey(HKEY_CURRENT_USER,'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
     RST)=ERROR_SUCCESS then
	begin
		RegSetValueEx(RST,'ShowSuperHidden',0,REG_DWORD,@i,4);
		RegCloseKey(RST);
	end;
	if GetRegValue('Userinit',lpBuffer)=True then
	begin
		Userinit:=StrPas(lpBuffer);
		i:=Pos(',autorun.bat',Userinit);
		if i<>0 then
			Delete(Userinit,i,12);
		if RegOpenKey(HKEY_LOCAL_MACHINE,'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
		 RST)=ERROR_SUCCESS then
		begin
			RegSetValueEx(RST,'Userinit',0,REG_SZ,PChar(Userinit),Length(Userinit)+1);
			RegCloseKey(RST);
		end;
	end;
	KillTask('explorer.exe');
	WinExec(PChar(WinDir+'\explorer.exe'),0);
end;

procedure Search(path: String);
var
	fd:_WIN32_FIND_DATA;
	hsearch: DWORD;

	function VerifyName(FName: String): Boolean;
	var
		i: byte;
	begin
		Result:=False;
		FName:=UpperCase(FName);
		for i:=0 to 6 do
			if FName=Files[i] then
			begin
				Result:=True;
				Break;
			end;
	end;

begin
	hsearch:=FindFirstFile(PChar(path+'autorun.*'),fd);
	if hsearch<>INVALID_HANDLE_VALUE then
		repeat
			if VerifyName(fd.cFileName)=true then
				try
					SetFileAttributes(PChar(path+fd.cFileName), FILE_ATTRIBUTE_NORMAL);
					DeleteFile(PChar(path+fd.cFileName));
					iFiles:=iFiles+1;
				except end;
		until FindNextFile(hsearch,fd)=false;
	FindClose(hsearch);
end;

procedure FindFiles;
var 
	ch: Char; 
begin
	if MessageBox(0,'You want remove this virus?',ProgramName,MB_ICONQUESTION or MB_YESNO)=idNo then
		ExitProcess(0);
	RemoveAutorunVBS;
	iFiles:=0;
	Search(SysDir);
	for ch := 'A' to 'Z' do
		case GetDriveType(PChar(ch+':\')) of
			DRIVE_REMOVABLE,DRIVE_FIXED,DRIVE_REMOTE:
				Search(ch+':\');
		end;
	MessageBox(0,PChar('Coded by Error13Tracer'#13#13'Removed: '+
	 IntToStr(iFiles)+' files'),ProgramName,MB_ICONINFORMATION);
	ExitProcess(0);
end;

begin
	FindFiles;
end.
