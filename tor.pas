unit tor;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs,
  DCPtwofish, DCPtea, DCPserpent, DCPrijndael,
  DCPrc6, DCPrc5, DCPrc4, DCPrc2, DCPmisty1, DCPmars, DCPidea, DCPice,
  DCPdes, DCPblockciphers, DCPcast256, DCPcast128, DCPcrypt2, DCPblowfish,
  DCPsha512,
  Registry,
  ShlObj,
  ClipBrd,
  shellapi,
  TextTrayIcon,
  XPMan,
  StdCtrls, ExtCtrls, ImgList, CoolTrayIcon, Menus, Buttons;

type
  TCRF = class(TForm)
    dlgOpen1: TOpenDialog;
    il1: TImageList;
    TrayIcon1: TTextTrayIcon;
    tmr1: TTimer;
    pm1: TPopupMenu;
    D1: TMenuItem;
    ListBox1: TListBox;
    grp2: TGroupBox;
    btn2: TButton;
    btn3: TButton;
    Button1: TButton;
    chk1: TCheckBox;
    chk2: TCheckBox;
    A1: TMenuItem;
    chk3: TCheckBox;
    N1: TMenuItem;
    copyDs: TSpeedButton;
    procedure btn2Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormActivate(Sender: TObject);
    procedure btn3Click(Sender: TObject);
    procedure TrayIcon1Click(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure FormDestroy(Sender: TObject);
    procedure tmr1Timer(Sender: TObject);
    procedure D1Click(Sender: TObject);
    procedure Button1Click(Sender: TObject);
    procedure chk1Click(Sender: TObject);
    procedure chk2Click(Sender: TObject);
    procedure ListBox1MouseMove(Sender: TObject; Shift: TShiftState; X,
      Y: Integer);
    procedure A1Click(Sender: TObject);
    procedure chk3Click(Sender: TObject);
    procedure N1Click(Sender: TObject);
    procedure copyDsClick(Sender: TObject);
  private
    function GFileSize(FileName: String): Integer;
    function IsFileInUse(const fName: TFileName): string;
    procedure WMQueryEndSession(var Message: TMessage); message WM_QUERYENDSESSION;
  public
    { Public declarations }
  protected
    { protected declarations }
    procedure WMDropFiles (var Msg: TMessage); message wm_DropFiles;
  end;

const //Для работы с реестром
  KEY_WOW64_64KEY = $0100;
  KEY_WOW64_32KEY = $0200;

var
  CRF: TCRF;
  fl: string;
  s: string; //имя файла для шифрования
  dostup: string;
  HM: THandle;
  MyStream :TFilestream;
  reg: TRegistry;
  FILE_LIST: TStringList;
  SENDMESSAGE_LIST: TStringList;
  KeyRelease:string = 'dj4lgmnitG4gggfdASEg45g4g3j7rK620N2YZYiX4 DT]'+
    '5rf7S/kMNm,n./OK/ilUN..u8h.H6fJFCj5DFNY6GMvbm,6FmTFMy6FMtfMy5fdN564BtErb'+
    '7gl7G,ubKTRF645djDRJ5Dmy76l8h;9J;9J;8hfUFCGcgD4f4SHxnYhb,nvnvchgFH5RUrfO'+
    'dskjhfpqo9s97hgBL7BL7bl7ghl7hGL87GLGl7l7glxdrgfcg58KHJghdfdrpPnbU'+
    'DJFDKSFghjyg;KH9bn6CRTXCx4hUGLB.8.nkVTJ6FJfjylk7gl7GLUHm'+
    'HG7gnkBk8jhKkKJHK87HkjkFGF6PCbV9KaK81WWYgP[CR[yjILWv2_SBE]AsLEz_8sBZ3LV5N'+
    'Go0NLL1om4 XbALjhgkk7sda823r23;d923NrUdkzPp5 DkJ2_8JvYmWFn LR3CRxyfswsto'+
    'cvnkscv78h2lk8HHKhlkjdfvsd;vlkvsd0vvds;ldvhyB[NXzl5y5Z';  

implementation

uses pw, key, infcrypt;

{$R *.dfm}

//Правильный выход с программы при перезагрузке Винды
procedure TCRF.WMQueryEndSession(var Message: TMessage);
begin
  Message.Result := 1;
  Application.Terminate;
end;

//Запрет повторного запуска
function Check: boolean;
begin
  HM := OpenMutex(MUTEX_ALL_ACCESS, false, 'CryptoSTELS');
  Result := (HM <> 0);
  if HM = 0 then
  HM := CreateMutex(nil, false, 'CryptoSTELS');
end;

// узнать занят ли файл другим  пользоваелем
function TCRF.IsFileInUse(const fName: TFileName): string;
var
  HFileRes: HFILE;
begin
 try
   Result := '';
   HFileRes := CreateFile(PChar(fName),
                          GENERIC_READ or GENERIC_WRITE,
                          0,
                          nil,
                          OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL,
                          0);
   if (HFileRes = INVALID_HANDLE_VALUE)=true then begin
       Result :='В данный момент файл занят';
       dostup:='В данный момент файл занят';
   end else begin
       Result :='В данный момент файл свободен';
       dostup:='В данный момент файл свободен';
   end;
     CloseHandle(HFileRes);
  except
  end;
end;

// получить размер файла
function TCRF.GFileSize(FileName: String): Integer;
var
  FS: TFileStream;
begin
  try
    FS := TFileStream.Create(Filename, fmOpenRead);
  except
    Result := -1;
  end;
  if Result <> -1 then Result := FS.Size;
  FS.Free;
end;

//Защита от отладчика
function DebuggerPresent:boolean;
type
  TDebugProc = function:boolean; stdcall;
var
   Kernel32:HMODULE;
   DebugProc:TDebugProc;
begin
   Result:=false;
   Kernel32:=GetModuleHandle('kernel32.dll');
   if kernel32 <> 0 then
    begin
      @DebugProc:=GetProcAddress(kernel32, 'IsDebuggerPresent');
      if Assigned(DebugProc) then
         Result:=DebugProc;
    end;
end;

//Узнать свою версию
function GetFileVersion(FileName: string; var VerInfo : TVSFixedFileInfo): boolean;
var
  InfoSize, puLen: DWORD;
  Pt, InfoPtr: Pointer;
begin
  InfoSize := GetFileVersionInfoSize( PChar(FileName), puLen );
  FillChar(VerInfo, SizeOf(TVSFixedFileInfo), 0);
  if InfoSize > 0 then
  begin
    GetMem(Pt,InfoSize);
    GetFileVersionInfo( PChar(FileName), 0, InfoSize, Pt);
    VerQueryValue(Pt,'\',InfoPtr,puLen);
    Move(InfoPtr^, VerInfo, sizeof(TVSFixedFileInfo) );
    FreeMem(Pt);
    Result := True;
  end
  else
    Result := False;
end;

function ShowVersion(FileName:string):string;
var
  VerInfo : TVSFixedFileInfo;
begin
  if GetFileVersion(FileName, VerInfo) then
    Result:=Format('%u.%u.%u.%u',[HiWord(VerInfo.dwProductVersionMS), LoWord(VerInfo.dwProductVersionMS),
      HiWord(VerInfo.dwProductVersionLS), LoWord(VerInfo.dwProductVersionLS)])
  else
    Result:='------';
end;

function EnableDebugPrivilege(const Value: Boolean): Boolean;
const
  SE_DEBUG_NAME = 'SeDebugPrivilege';
var
  hToken: THandle;
  tp: TOKEN_PRIVILEGES;
  d: DWORD;
begin
  Result := False;
  if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, hToken) then
  begin
    tp.PrivilegeCount := 1;
    LookupPrivilegeValue(nil, SE_DEBUG_NAME, tp.Privileges[0].Luid);
    if Value then
      tp.Privileges[0].Attributes := $00000002
    else
      tp.Privileges[0].Attributes := $80000000;
    AdjustTokenPrivileges(hToken, False, tp, SizeOf(TOKEN_PRIVILEGES), nil, d);
    if GetLastError = ERROR_SUCCESS then
    begin
      Result := True;
    end;
    CloseHandle(hToken);
  end;
end;

procedure CreateFormInRightBottomCorner;
var
 r : TRect;
begin
 SystemParametersInfo(SPI_GETWORKAREA, 0, Addr(r), 0);
 CRF.Left := r.Right-CRF.Width;
 CRF.Top := r.Bottom-CRF.Height;
end;

// чтение из реестра
function RegQueryStr(RootKey: HKEY; Key, Name: string;
  Success: PBoolean = nil): string;
var
  Handle: HKEY;
  Res: LongInt;
  DataType, DataSize: DWORD;
begin
  if Assigned(Success) then
    Success^ := False;
  Res := RegOpenKeyEx(RootKey, PChar(Key), 0, KEY_QUERY_VALUE, Handle);
  if Res <> ERROR_SUCCESS then
    Exit;
  Res := RegQueryValueEx(Handle, PChar(Name), nil, @DataType, nil, @DataSize);
  if (Res <> ERROR_SUCCESS) or (DataType <> REG_SZ) then
  begin
    RegCloseKey(Handle);
    Exit;
  end;
  SetString(Result, nil, DataSize - 1);
  Res := RegQueryValueEx(Handle, PChar(Name), nil, @DataType, @Result[1], @DataSize);
  if Assigned(Success) then
    Success^ := Res = ERROR_SUCCESS;
  RegCloseKey(Handle);
end;

// запись в реестра
function RegWriteStr(RootKey: HKEY; Key, Name, Value: string): Boolean;
var
  Handle: HKEY;
  Res: LongInt;
begin
  Result := False;
  Res := RegCreateKeyEx(RootKey, PChar(Key), 0, nil, REG_OPTION_NON_VOLATILE,
    KEY_ALL_ACCESS, nil, Handle, nil);
  if Res <> ERROR_SUCCESS then
    Exit;
  Res := RegSetValueEx(Handle, PChar(Name), 0, REG_SZ, PChar(Value),
    Length(Value) + 1);
  Result := Res = ERROR_SUCCESS;
  RegCloseKey(Handle);
end;

function GetFileDateTime(FileName: string): TDateTime;
var
  intFileAge: LongInt;
begin
  intFileAge := FileAge(FileName);
  if intFileAge = -1 then
    Result := 0
  else
    Result := FileDateToDateTime(intFileAge)
end;

//Поиск дисков на компе
function GetDriveVolume(Drive: string): string;
var
  _VolumeName, _FileSystemName: array [0..MAX_PATH - 1] of Char;
  _VolumeSerialNo, _MaxComponentLength, _FileSystemFlags: LongWord;
begin
  Result := '';
  if GetVolumeInformation(PChar(Drive + ':\'), _VolumeName, MAX_PATH,
    @_VolumeSerialNo, _MaxComponentLength ,_FileSystemFlags,
    _FileSystemName, MAX_PATH)
  then
    Result := _VolumeName;
end;

procedure GetDriveList(StringList: TStringList);
var
  DriveList: TStringList;
  Drive: Char;
  I: Integer;
begin
  FILE_LIST.Clear;
  DriveList := TStringList.Create;
  for Drive := 'a' to 'z' do
  begin
    case GetDriveType(PChar(Drive + ':\')) of
      DRIVE_REMOVABLE:
        begin
          FILE_LIST.Add(UpCase(Drive) + ':\');
          if GetDriveVolume(Drive) <> '' then
            DriveList.Add(UpCase(Drive) + ': (' + GetDriveVolume(Drive) + ')')
          else
            DriveList.Add(UpCase(Drive) + ': (' + 'DRIVE_REMOVABLE)');
        end;
      DRIVE_FIXED:
        begin
          FILE_LIST.Add(UpCase(Drive) + ':\');
          if GetDriveVolume(Drive) <> '' then
            DriveList.Add(UpCase(Drive) + ': (' + GetDriveVolume(Drive) + ')')
          else
            DriveList.Add(UpCase(Drive) + ': (' + 'DRIVE_FIXED)');
        end;
      DRIVE_CDROM:
        begin
          FILE_LIST.Add(UpCase(Drive) + ':\');
          if GetDriveVolume(Drive) <> '' then
            DriveList.Add(UpCase(Drive) + ': (' + GetDriveVolume(Drive) + ')')
          else
            DriveList.Add(UpCase(Drive) + ': (' + 'DRIVE_CDROM)');
        end;
      DRIVE_RAMDISK:
        begin
          FILE_LIST.Add(UpCase(Drive) + ':\');
          if GetDriveVolume(Drive) <> '' then
            DriveList.Add(UpCase(Drive) + ': (' + GetDriveVolume(Drive) + ')')
          else
            DriveList.Add(UpCase(Drive) + ': (' + 'DRIVE_RAMDISK)');
        end;
      DRIVE_REMOTE:
        begin
          FILE_LIST.Add(UpCase(Drive) + ':\');
          if GetDriveVolume(Drive) <> '' then
            DriveList.Add(UpCase(Drive) + ': (' + GetDriveVolume(Drive) + ')')
          else
            DriveList.Add(UpCase(Drive) + ': (' + 'DRIVE_REMOTE)');
        end;
    end;
  end;
  FILE_LIST.Sort;
  DriveList.Sort;
  for I := 0 to DriveList.Count - 1 do
  SENDMESSAGE_LIST.Add(Format('%d - %s', [I + 1, DriveList.Strings[I]]));
  DriveList.Free;
end;

//Файл без расширения
function ExtractOnlyFileName(const FileName: string): string;
begin
  result:=StringReplace(ExtractFileName(FileName),ExtractFileExt(FileName),'',[]);
end;

function ShortToLongFileName(FileName: string): string;
var
  KernelHandle: THandle;
  FindData: TWin32FindData;
  Search: THandle;
  GetLongPathName: function(lpszShortPath: PChar; lpszLongPath: PChar;
                           cchBuffer: DWORD): DWORD; stdcall;
begin
  KernelHandle := GetModuleHandle('KERNEL32');
  if KernelHandle <> 0 then
    @GetLongPathName:=GetProcAddress(KernelHandle, 'GetLongPathNameA');
  if Assigned(GetLongPathName) then
    begin
      SetLength(Result, MAX_PATH + 1);
      SetLength(Result, GetLongPathName(PChar(FileName), @Result[1], MAX_PATH))
    end
  else
    begin
      Result:='';
      while (true) do
         begin
           Search := Windows.FindFirstFile(PChar(FileName), FindData);
           if Search = INVALID_HANDLE_VALUE then Break;
              Result := String('\') + FindData.cFileName + Result;
              FileName := ExtractFileDir(FileName);
              ShowMessage(FileName+'0000');
              Windows.FindClose(Search);
           if Length(FileName) <= 2 then Break
         end;
      Result := ExtractFileDrive(FileName) + Result
    end
end;

//Зашифрование/расшифрование файла:
function EncryptFile(Source, Dest, Password: string): Boolean;
var
  DCP_rijndael1: TDCP_rijndael;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_rijndael1 := TDCP_rijndael.Create(nil);
    DCP_rijndael1.InitStr(Password, TDCP_sha512);
    DCP_rijndael1.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_rijndael1.Burn;
    DCP_rijndael1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile(Source, Dest, Password: string): Boolean;
var
  DCP_rijndael1: TDCP_rijndael;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_rijndael1 := TDCP_rijndael.Create(nil);
    DCP_rijndael1.InitStr(Password, TDCP_sha512);
    DCP_rijndael1.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_rijndael1.Burn;
    DCP_rijndael1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_blowfish(Source, Dest, Password: string): Boolean;
var
  DCP_blowfish1: TDCP_blowfish;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_blowfish1 := TDCP_blowfish.Create(nil);
    DCP_blowfish1.InitStr(Password, TDCP_sha512);
    DCP_blowfish1.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_blowfish1.Burn;
    DCP_blowfish1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_blowfish(Source, Dest, Password: string): Boolean;
var
  DCP_blowfish1: TDCP_blowfish;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_blowfish1 := TDCP_blowfish.Create(nil);
    DCP_blowfish1.InitStr(Password, TDCP_sha512);
    DCP_blowfish1.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_blowfish1.Burn;
    DCP_blowfish1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_cast128(Source, Dest, Password: string): Boolean;
var
  DCP_cast1281: TDCP_cast128;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_cast1281 := TDCP_cast128.Create(nil);
    DCP_cast1281.InitStr(Password, TDCP_sha512);
    DCP_cast1281.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_cast1281.Burn;
    DCP_cast1281.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_cast128(Source, Dest, Password: string): Boolean;
var
  DCP_cast1281: TDCP_cast128;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_cast1281 := TDCP_cast128.Create(nil);
    DCP_cast1281.InitStr(Password, TDCP_sha512);
    DCP_cast1281.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_cast1281.Burn;
    DCP_cast1281.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_cast256(Source, Dest, Password: string): Boolean;
var
  DCP_cast2561: TDCP_cast256;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_cast2561 := TDCP_cast256.Create(nil);
    DCP_cast2561.InitStr(Password, TDCP_sha512);
    DCP_cast2561.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_cast2561.Burn;
    DCP_cast2561.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_cast256(Source, Dest, Password: string): Boolean;
var
  DCP_cast2561: TDCP_cast256;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_cast2561 := TDCP_cast256.Create(nil);
    DCP_cast2561.InitStr(Password, TDCP_sha512);
    DCP_cast2561.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_cast2561.Burn;
    DCP_cast2561.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_des(Source, Dest, Password: string): Boolean;
var
  DCP_des1: TDCP_des;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_des1 := TDCP_des.Create(nil);
    DCP_des1.InitStr(Password, TDCP_sha512);
    DCP_des1.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_des1.Burn;
    DCP_des1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_des(Source, Dest, Password: string): Boolean;
var
  DCP_des1: TDCP_des;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_des1 := TDCP_des.Create(nil);
    DCP_des1.InitStr(Password, TDCP_sha512);
    DCP_des1.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_des1.Burn;
    DCP_des1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_3des(Source, Dest, Password: string): Boolean;
var
  DCP_3des1: TDCP_3des;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_3des1 := TDCP_3des.Create(nil);
    DCP_3des1.InitStr(Password, TDCP_sha512);
    DCP_3des1.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_3des1.Burn;
    DCP_3des1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_3des(Source, Dest, Password: string): Boolean;
var
  DCP_3des1: TDCP_3des;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_3des1 := TDCP_3des.Create(nil);
    DCP_3des1.InitStr(Password, TDCP_sha512);
    DCP_3des1.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_3des1.Burn;
    DCP_3des1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_ice(Source, Dest, Password: string): Boolean;
var
  DCP_ice1: TDCP_ice;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_ice1 := TDCP_ice.Create(nil);
    DCP_ice1.InitStr(Password, TDCP_sha512);
    DCP_ice1.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_ice1.Burn;
    DCP_ice1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_ice(Source, Dest, Password: string): Boolean;
var
  DCP_ice1: TDCP_ice;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_ice1 := TDCP_ice.Create(nil);
    DCP_ice1.InitStr(Password, TDCP_sha512);
    DCP_ice1.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_ice1.Burn;
    DCP_ice1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_thinice(Source, Dest, Password: string): Boolean;
var
  DCP_thinice1: TDCP_thinice;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_thinice1 := TDCP_thinice.Create(nil);
    DCP_thinice1.InitStr(Password, TDCP_sha512);
    DCP_thinice1.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_thinice1.Burn;
    DCP_thinice1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_thinice(Source, Dest, Password: string): Boolean;
var
  DCP_thinice1: TDCP_thinice;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_thinice1 := TDCP_thinice.Create(nil);
    DCP_thinice1.InitStr(Password, TDCP_sha512);
    DCP_thinice1.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_thinice1.Burn;
    DCP_thinice1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_ice2(Source, Dest, Password: string): Boolean;
var
  DCP_ice21: TDCP_ice2;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_ice21 := TDCP_ice2.Create(nil);
    DCP_ice21.InitStr(Password, TDCP_sha512);
    DCP_ice21.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_ice21.Burn;
    DCP_ice21.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_ice2(Source, Dest, Password: string): Boolean;
var
  DCP_ice21: TDCP_ice2;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_ice21 := TDCP_ice2.Create(nil);
    DCP_ice21.InitStr(Password, TDCP_sha512);
    DCP_ice21.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_ice21.Burn;
    DCP_ice21.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_idea(Source, Dest, Password: string): Boolean;
var
  DCP_idea1: TDCP_idea;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_idea1 := TDCP_idea.Create(nil);
    DCP_idea1.InitStr(Password, TDCP_sha512);
    DCP_idea1.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_idea1.Burn;
    DCP_idea1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_idea(Source, Dest, Password: string): Boolean;
var
  DCP_idea1: TDCP_idea;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_idea1 := TDCP_idea.Create(nil);
    DCP_idea1.InitStr(Password, TDCP_sha512);
    DCP_idea1.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_idea1.Burn;
    DCP_idea1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_mars(Source, Dest, Password: string): Boolean;
var
  DCP_mars1: TDCP_mars;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_mars1 := TDCP_mars.Create(nil);
    DCP_mars1.InitStr(Password, TDCP_sha512);
    DCP_mars1.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_mars1.Burn;
    DCP_mars1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_mars(Source, Dest, Password: string): Boolean;
var
  DCP_mars1: TDCP_mars;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_mars1 := TDCP_mars.Create(nil);
    DCP_mars1.InitStr(Password, TDCP_sha512);
    DCP_mars1.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_mars1.Burn;
    DCP_mars1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_misty1(Source, Dest, Password: string): Boolean;
var
  DCP_misty11: TDCP_misty1;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_misty11 := TDCP_misty1.Create(nil);
    DCP_misty11.InitStr(Password, TDCP_sha512);
    DCP_misty11.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_misty11.Burn;
    DCP_misty11.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_misty1(Source, Dest, Password: string): Boolean;
var
  DCP_misty11: TDCP_misty1;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_misty11 := TDCP_misty1.Create(nil);
    DCP_misty11.InitStr(Password, TDCP_sha512);
    DCP_misty11.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_misty11.Burn;
    DCP_misty11.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_rc2(Source, Dest, Password: string): Boolean;
var
  DCP_rc21: TDCP_rc2;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_rc21 := TDCP_rc2.Create(nil);
    DCP_rc21.InitStr(Password, TDCP_sha512);
    DCP_rc21.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_rc21.Burn;
    DCP_rc21.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_rc2(Source, Dest, Password: string): Boolean;
var
  DCP_rc21: TDCP_rc2;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_rc21 := TDCP_rc2.Create(nil);
    DCP_rc21.InitStr(Password, TDCP_sha512);
    DCP_rc21.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_rc21.Burn;
    DCP_rc21.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_rc4(Source, Dest, Password: string): Boolean;
var
  DCP_rc41: TDCP_rc4;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_rc41 := TDCP_rc4.Create(nil);
    DCP_rc41.InitStr(Password, TDCP_sha512);
    DCP_rc41.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_rc41.Burn;
    DCP_rc41.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_rc4(Source, Dest, Password: string): Boolean;
var
  DCP_rc41: TDCP_rc4;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_rc41 := TDCP_rc4.Create(nil);
    DCP_rc41.InitStr(Password, TDCP_sha512);
    DCP_rc41.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_rc41.Burn;
    DCP_rc41.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_rc5(Source, Dest, Password: string): Boolean;
var
  DCP_rc51: TDCP_rc5;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_rc51 := TDCP_rc5.Create(nil);
    DCP_rc51.InitStr(Password, TDCP_sha512);
    DCP_rc51.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_rc51.Burn;
    DCP_rc51.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_rc5(Source, Dest, Password: string): Boolean;
var
  DCP_rc51: TDCP_rc5;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_rc51 := TDCP_rc5.Create(nil);
    DCP_rc51.InitStr(Password, TDCP_sha512);
    DCP_rc51.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_rc51.Burn;
    DCP_rc51.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_rc6(Source, Dest, Password: string): Boolean;
var
  DCP_rc61: TDCP_rc6;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_rc61 := TDCP_rc6.Create(nil);
    DCP_rc61.InitStr(Password, TDCP_sha512);
    DCP_rc61.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_rc61.Burn;
    DCP_rc61.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_rc6(Source, Dest, Password: string): Boolean;
var
  DCP_rc61: TDCP_rc6;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_rc61 := TDCP_rc6.Create(nil);
    DCP_rc61.InitStr(Password, TDCP_sha512);
    DCP_rc61.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_rc61.Burn;
    DCP_rc61.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_serpent(Source, Dest, Password: string): Boolean;
var
  DCP_serpent1: TDCP_serpent;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_serpent1 := TDCP_serpent.Create(nil);
    DCP_serpent1.InitStr(Password, TDCP_sha512);
    DCP_serpent1.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_serpent1.Burn;
    DCP_serpent1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_serpent(Source, Dest, Password: string): Boolean;
var
  DCP_serpent1: TDCP_serpent;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_serpent1 := TDCP_serpent.Create(nil);
    DCP_serpent1.InitStr(Password, TDCP_sha512);
    DCP_serpent1.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_serpent1.Burn;
    DCP_serpent1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_tea(Source, Dest, Password: string): Boolean;
var
  DCP_tea1: TDCP_tea;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_tea1 := TDCP_tea.Create(nil);
    DCP_tea1.InitStr(Password, TDCP_sha512);
    DCP_tea1.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_tea1.Burn;
    DCP_tea1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_tea(Source, Dest, Password: string): Boolean;
var
  DCP_tea1: TDCP_tea;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_tea1 := TDCP_tea.Create(nil);
    DCP_tea1.InitStr(Password, TDCP_sha512);
    DCP_tea1.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_tea1.Burn;
    DCP_tea1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function EncryptFile_twofish(Source, Dest, Password: string): Boolean;
var
  DCP_twofish1: TDCP_twofish;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_twofish1 := TDCP_twofish.Create(nil);
    DCP_twofish1.InitStr(Password, TDCP_sha512);
    DCP_twofish1.EncryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_twofish1.Burn;
    DCP_twofish1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

function DecryptFile_twofish(Source, Dest, Password: string): Boolean;
var
  DCP_twofish1: TDCP_twofish;
  SourceStream, DestStream: TFileStream;
begin
  Result := True;
  try
    SourceStream := TFileStream.Create(Source, fmOpenRead);
    DestStream := TFileStream.Create(Dest, fmCreate);
    DCP_twofish1 := TDCP_twofish.Create(nil);
    DCP_twofish1.InitStr(Password, TDCP_sha512);
    DCP_twofish1.DecryptStream(SourceStream, DestStream, SourceStream.Size);
    DCP_twofish1.Burn;
    DCP_twofish1.Free;
    DestStream.Free;
    SourceStream.Free;
  except
    Result := False;
  end;
end;

procedure EncrypTOR;
var
  i: integer; //18 методов шифрования
  reg: TRegistry;
begin
   Randomize;
   i:=Random(18);
if not CRF.chk1.Checked then
if fl <> '' then
   fl:=s;
if ExtractFileExt(s) = '.sts' then begin
   CRF.ListBox1.Items.Add('Файл лицензии нельзя шифровать!'); //MessageBox(0, 'Файл лицензии нельзя шифровать!','Внимание', MB_ICONINFORMATION or MB_OK);
   exit;
end;
//Снимаем блокировку с файла
if s <> '' then RegWriteStr(HKEY_CLASSES_ROOT,'LockF','FileUnLock','0');
   if ExtractFileExt(s) = '.blowfish' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!'); //CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   CRF.il1.GetIcon(2, Application.Icon); //Меняем иконку в программе
   if ExtractFileExt(s) = '.Cast128' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.Cast256' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.Des' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.3Des' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.Ice' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.Thinice' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.Ice2' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.Idea' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.Mars' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.Misty1' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.RC2' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.RC4' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.RC6' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.Rijndael' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.Serpent' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.TEA' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.Twofish' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
   if ExtractFileExt(s) = '.RC5' then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s)+' уже зашифрован!');
      exit;
   end;
if i = 0 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!'); //MessageBox(0, 'Шифровать себя нельзя!!!','Внимание', MB_ICONINFORMATION or MB_OK);
      exit;
   end else begin
      EncryptFile_blowfish(s,s+'.blowfish',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается параметр со значением "!txt", если его нет
      if reg.openkey('.blowfish',true) then
      reg.writestring('', '!blowfish');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!blowfish\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS; 
      if reg.openkey('!blowfish\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 1 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_Cast128(s,s+'.Cast128',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".Cast128", если его нет
      if reg.openkey('.Cast128',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!Cast128');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Cast128\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Cast128\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 2 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_Cast256(s,s+'.Cast256',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".Cast256", если его нет
      if reg.openkey('.Cast256',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!Cast256');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Cast256\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Cast256\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 3 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_Des(s,s+'.Des',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".Des", если его нет
      if reg.openkey('.Des',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!Des');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Des\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      if reg.openkey('!Des\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 4 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_3Des(s,s+'.3Des',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".3Des", если его нет
      if reg.openkey('.3Des',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!3Des');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!3Des\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!3Des\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 5 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_Ice(s,s+'.Ice',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".Ice", если его нет
      if reg.openkey('.Ice',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!Ice');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Ice\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Ice\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 6 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_Thinice(s,s+'.Thinice',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".Thinice", если его нет
      if reg.openkey('.Thinice',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!Thinice');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Thinice\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Thinice\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 7 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_Ice2(s,s+'.Ice2',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".Ice2", если его нет
      if reg.openkey('.Ice2',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!Ice2');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Ice2\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Ice2\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 8 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_Idea(s,s+'.Idea',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".Idea", если его нет
      if reg.openkey('.Idea',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!Idea');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Idea\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Idea\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 9 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_Mars(s,s+'.Mars',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".Mars", если его нет
      if reg.openkey('.Mars',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!Mars');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Mars\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Mars\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 10 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_Misty1(s,s+'.Misty1',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".Misty1", если его нет
      if reg.openkey('.Misty1',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!Misty1');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Misty1\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Misty1\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 11 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_RC2(s,s+'.RC2',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".RC2", если его нет
      if reg.openkey('.RC2',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!RC2');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!RC2\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!RC2\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 12 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_RC4(s,s+'.RC4',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".RC4", если его нет
      if reg.openkey('.RC4',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!RC4');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!RC4\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!RC4\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;

   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 13 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_RC5(s,s+'.RC5',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".RC5", если его нет
      if reg.openkey('.RC5',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!RC5');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!RC5\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!RC5\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 14 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_RC6(s,s+'.RC6',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".RC6", если его нет
      if reg.openkey('.RC6',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!RC6');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!RC6\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!RC6\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;

   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 15 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile(s,s+'.Rijndael',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".Rijndael", если его нет
      if reg.openkey('.Rijndael',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!Rijndael');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Rijndael\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Rijndael\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;

   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 16 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_Serpent(s,s+'.Serpent',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".Serpent", если его нет
      if reg.openkey('.Serpent',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!Serpent');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Serpent\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Serpent\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 17 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_TEA(s,s+'.TEA',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".Serpent", если его нет
      if reg.openkey('.TEA',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!TEA');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!TEA\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!TEA\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
if i = 18 then begin
   if s = ParamStr(0) then begin
      CRF.ListBox1.Items.Add('Шифровать себя нельзя!');
      exit;
   end else begin
      EncryptFile_Twofish(s,s+'.Twofish',KeyRelease);
      DeleteFile(s);
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно зашифрован!'));
   try
  ///////////Добавляем отображаемую иконку/////////////
      reg := TRegistry.Create(KEY_ALL_ACCESS or KEY_WOW64_64KEY); //создаем переменую
    // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    //Открываем доступ к реестру
      reg.Access := KEY_ALL_ACCESS;
    // создается ключ ".Twofish", если его нет
      if reg.openkey('.Twofish',true) then
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!Twofish');
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Twofish\defaulticon',true) then
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.Access := KEY_ALL_ACCESS;
      if reg.openkey('!Twofish\shell\open\command', true) then
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
   finally
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
   end;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
   end;
end;
s:='';
end;

procedure DecrypTOR;
var
  s1: string;
begin
   CRF.il1.GetIcon(3, Application.Icon); //Меняем иконку в программе
   InvalidateRect(Application.Handle, NIL, true);
   if s <> '' then fl := s;
   if fl <> ParamStr(0) then s:=fl;
      s1:=ExtractFilePath(s)+ExtractOnlyFileName(s);
  ////////////////////////////////////////////////
   if ExtractFileExt(s) = '.blowfish' then begin
      DecryptFile_blowfish(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.blowfish') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.Cast128' then begin      
      DecryptFile_Cast128(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.Cast128') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.Cast256' then begin
      DecryptFile_Cast256(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.Cast256') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.Des' then begin
      DecryptFile_Des(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.Des') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.3Des' then begin
      DecryptFile_3Des(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.3Des') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.Ice' then begin
      DecryptFile_Ice(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.Ice') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.Thinice' then begin
      DecryptFile_Thinice(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.Thinice') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.Ice2' then begin
      DecryptFile_Ice2(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.Ice2') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.Idea' then begin
      DecryptFile_Idea(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.Idea') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.Mars' then begin
      DecryptFile_Mars(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.Mars') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.Misty1' then begin
      DecryptFile_Misty1(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.Misty1') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.RC2' then begin
      DecryptFile_RC2(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.RC2') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.RC4' then begin
      DecryptFile_RC4(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.RC4') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.RC5' then begin
      DecryptFile_RC5(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.RC5') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.RC6' then begin
      DecryptFile_RC6(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.RC6') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.Rijndael' then begin
      DecryptFile(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.Rijndael') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.Serpent' then begin
      DecryptFile_Serpent(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.Serpent') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.TEA' then begin
      DecryptFile_TEA(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.TEA') and FileExists(s) then DeleteFile(s);
   end;
   if ExtractFileExt(s) = '.Twofish' then begin
      DecryptFile_Twofish(s,s1,KeyRelease);
   if FileExists(s) then begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' успешно расшифрован!'));
   end else begin
      CRF.ListBox1.Items.Add('Файл '+ExtractFileName(s+' заблокирован!'+#13#10+'Для расшифровки сначало разблокируйте файл!'));
   end;
   if (ExtractFileExt(s) = '.Twofish') and FileExists(s) then DeleteFile(s);
   end;
  ////////////////////////////////////////////////
end;

procedure TCRF.btn2Click(Sender: TObject);
begin
   il1.GetIcon(2, Application.Icon); //Меняем иконку в программе
   CreateFormInRightBottomCorner;
if CRF.dlgOpen1.Execute then begin
   s:=CRF.dlgOpen1.FileName;
   fl:=CRF.dlgOpen1.FileName;
end;
if fl <> ParamStr(0) then begin
if fl <> '' then
   EncrypTOR; 
end;
end;

//процедура получения файлов из дерриктории
procedure FileDir(Path: string; FileList: TStrings);
 var
   SR: TSearchRec;
 begin
   if not FileExists(Path) then begin
   if FindFirst(Path+'\*.*', faAnyFile, SR) = 0 then begin
     repeat
       if (SR.Attr <> faDirectory) then
       begin
         s:= Path +'\'+ SR.Name;
       if FileExists(s) then
       if CRF.chk1.Checked then EncrypTOR;
       if CRF.chk2.Checked then DecrypTOR;
       if (not CRF.chk1.Checked) and
          (not CRF.chk2.Checked) then FileList.Add(SR.Name);
       end;
     until FindNext(SR) <> 0;
     FindClose(SR);
   end;
   end else begin
   if FindFirst(Path, faAnyFile, SR) = 0 then begin
     repeat
       if (SR.Attr <> faDirectory) then
       begin
         s:= Path;
       if FileExists(s) then
       if CRF.chk1.Checked then EncrypTOR;
       if CRF.chk2.Checked then DecrypTOR;
       if (not CRF.chk1.Checked) and
          (not CRF.chk2.Checked) then FileList.Add(SR.Name);
       end;
     until FindNext(SR) <> 0;
     FindClose(SR);
   end;
   end;
 end;

//модифицированная процедура WMDropFiles
procedure TCRF.WMDropFiles(var Msg: TMessage);
var
  i, amount, size: integer;
  Filename: PChar;
  m:integer;
begin
inherited;
  Amount := DragQueryFile(Msg.WParam, $FFFFFFFF, Filename, 255);
for i := 0 to (Amount - 1) do
  begin
    size := DragQueryFile(Msg.WParam, i, nil, 0) + 1;
    Filename := StrAlloc(size);
    DragQueryFile(Msg.WParam, i, Filename, size);
    s:=Filename;
    m:=length(s);
    delete(s,1,m-4);
  if FileExists(Filename) then begin //listbox1.items.add(StrPas(Filename));
     s:=Filename;
  if CRF.chk1.Checked then EncrypTOR;
  if CRF.chk2.Checked then DecrypTOR;
  end else FileDir(Filename, ListBox1.Items); // получаем все * из папки  +'\'
  end;
    DragFinish(Msg.WParam);
end;

function DigestToStr(Digest: array of byte): string;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to 6 do
    Result := Result + LowerCase(IntToHex(Digest[i], 2));
end;

function Getsha1FromString(Source: string): string;
var
  Hash: TDCP_sha512;
  Digest: array[0..190] of Byte;
begin
  Hash := TDCP_sha512.Create(nil); // создаём объект
  Hash.Init;                      // инициализируем
  Hash.UpdateStr(Source);         // вычисляем хэш-сумму
  Hash.Final(Digest);             // сохраняем её в массив
  Hash.Free;                      // уничтожаем объект
  Result := DigestToStr(Digest);  // получаем хэш-сумму строкой
end;

procedure TCRF.FormCreate(Sender: TObject);
var
  i: Integer;
  s,vr: string;
  s2:string;
  m2:integer;
begin
  FILE_LIST:= TStringList.Create;
  SENDMESSAGE_LIST:= TStringList.Create;
  GetDriveList(FILE_LIST);
  //=====Защита от отладчика===========
  if DebuggerPresent then Application.Terminate;
  if Check then Application.Terminate;
   EnableDebugPrivilege(true);
   vr:=ShowVersion(Application.ExeName);
   CRF.Caption:='СrypTOR v'+vr;
   CreateFormInRightBottomCorner;
   il1.GetIcon(6, Application.Icon); //Меняем иконку в программе
   InvalidateRect(Application.Handle, NIL, true);
   fl:=ParamStr(0);
  if fl = '' then begin
     MessageBox(0, 'Нет пути к файлу!!!','Внимание', MB_ICONINFORMATION or MB_OK);
     Exit;
  end;
   DragAcceptFiles(Handle, true);
  //-------
  if ParamCount<>0 then begin
     s2:=ParamStr(1);
     m2:=length(s2);
     delete(s2,1,m2-4);
  if s2='*.*' then listbox1.items.add(ParamStr(1))
  else showmessage('Данный тип файла не поддерживаеться!');
  end;
  //--------
  if paramcount > 0 then
    begin
    //Определяем все параметры
    for i := 1 to ParamCount do begin
        s:=s+' '+ParamStr(i);
    end;
    if fileexists(paramstr(1)) then begin
       fl:=ShortToLongFileName(paramstr(1));
    end;
    if s <> '' then begin
       s:=Trim(s);
       fl:=PChar(s);
    end;
    end;
    grp2.Caption:='lic: '+Getsha1FromString(keys.crc);
end;

procedure TCRF.FormActivate(Sender: TObject);
var
 si,sn2: string;
begin
      sn2:=RegQueryStr(HKEY_CLASSES_ROOT,si,'CryptF');
  if (sn2 = '1') and (keys.crc = '') then begin
    MessageBox(Handle,'На этом компьютере ключ доступа уже был получен!','Внимание',64);
    Application.Terminate;
  end;
  //=====Защита от отладчика===========
  if DebuggerPresent then Application.Terminate;
     CreateFormInRightBottomCorner;
     CRF.FormStyle:=fsStayOnTop;
  if fl <> ParamStr(0) then begin
     il1.GetIcon(3, Application.Icon); //Меняем иконку в программе
  if fl <> '' then
     DecrypTOR;
  end;
     il1.GetIcon(6, Application.Icon); //Меняем иконку в программе
end;

procedure TCRF.btn3Click(Sender: TObject);
begin
  fl:='';
  ListBox1.Clear;
  chk1.Checked:=False;
  chk2.Checked:=False;
  CRF.FormStyle:=fsNormal;
  myps.Show;
end;

procedure TCRF.TrayIcon1Click(Sender: TObject);
begin
  CRF.Show;
  ListBox1.Clear;
  TrayIcon1.HideTaskbarIcon;
end;

procedure TCRF.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  CanClose:=False;
  CRF.Hide;
end;

procedure TCRF.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  EnableDebugPrivilege(False);
  TrayIcon1.HideTaskbarIcon;
  TrayIcon1.Free;
end;

procedure TCRF.FormDestroy(Sender: TObject);
begin
  FILE_LIST.Free;
  SENDMESSAGE_LIST.Free;
  TrayIcon1.HideTaskbarIcon;
end;

procedure TCRF.tmr1Timer(Sender: TObject);
begin
  //=====Защита от отладчика===========
  if DebuggerPresent then Application.Terminate;
end;

procedure TCRF.D1Click(Sender: TObject);
begin
  Application.Terminate;
end;

procedure TCRF.Button1Click(Sender: TObject);
begin
   Button1.Tag:=10;
   il1.GetIcon(3, Application.Icon); //Меняем иконку в программе
if CRF.dlgOpen1.Execute then begin
   fl:=CRF.dlgOpen1.FileName;
if ExtractFileExt(fl) = '.sts' then begin
   MessageBox(0, 'Файл лицензии нельзя расшифровать!','Внимание', MB_ICONINFORMATION or MB_OK);
   exit;
end;
end;
if fl <> ParamStr(0) then begin
if fl <> '' then
   DecrypTOR;
end;
   il1.GetIcon(2, Application.Icon); //Меняем иконку в программе
end;

procedure TCRF.chk1Click(Sender: TObject);
begin
 if chk1.Checked then begin
    chk2.Checked:=false;
    btn2.Enabled:=False;
    Button1.Enabled:=False;
 end else begin
    btn2.Enabled:=True;
    Button1.Enabled:=True;
 end;
end;

procedure TCRF.chk2Click(Sender: TObject);
begin
 if chk2.Checked then begin
    chk1.Checked:=false;
    btn2.Enabled:=False;
    Button1.Enabled:=False;
 end else begin
    btn2.Enabled:=True;
    Button1.Enabled:=True;
 end;   
end;

procedure TCRF.ListBox1MouseMove(Sender: TObject; Shift: TShiftState; X,
  Y: Integer);
var Point:TPoint; 
t:Integer; 
begin 
Point.X:=X; 
Point.Y:=Y; 
With ListBox1 Do 
Begin 
t:=ItemAtPos(Point,True); 
IF t>-1 then 
Begin 
// Если размер надписи превышает длину контрола, загружаем его значение в хинт 
IF Canvas.TextWidth(Items[t])>Width then Hint:=Items[t] else Application.CancelHint; 
End Else Application.CancelHint; 
End;
end;

procedure TCRF.A1Click(Sender: TObject);
begin
 RegWriteStr(HKEY_CURRENT_USER,'Software\Microsoft\Windows\CurrentVersion\Run','CrypTOR',ParamStr(0));
end;

procedure TCRF.chk3Click(Sender: TObject);
var
  FullProgPath: PChar;
begin
  if chk3.Checked then begin
     CloseHandle(HM);
     MyStream.Free;
     // снимаем блокировку области памяти занятую Clipboard-ом
     GlobalUnlock(myps.MyHandle);
     // закрываем Clipboard
     Clipboard.Close;
     FullProgPath:=PChar(Application.ExeName);
     WinExec(FullProgPath,SW_SHOW);
     Application.Terminate;
  end;
end;

procedure TCRF.N1Click(Sender: TObject);
begin
  MessageBox(Handle,PChar('Developer program StalkerSTS'+#13#10+'E-mail: stasbalazuk@gmail.com'),PChar('About'),64);
end;

procedure TCRF.copyDsClick(Sender: TObject);
var
 i: integer;
 s: string;
begin
  for i:=0 to FILE_LIST.Count-1 do begin
      s:=FILE_LIST.Strings[i];
  if FileExists(ExtractFilePath(ParamStr(0))+'mypass.ini.Rij') then
     CopyFile(PChar(ExtractFilePath(ParamStr(0))+'mypass.ini.Rij'),PChar(s+'mypass.ini.Rij'),False);
  if FileExists(s+'mypass.ini.Rij') then ListBox1.Items.Add('Файл mypass.ini.Rij успешно скопирован на диск '+s);
  end;
  for i:=0 to SENDMESSAGE_LIST.Count-1 do begin
      s:=SENDMESSAGE_LIST.Strings[i];
  end;
end;

end.
