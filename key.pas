unit key;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, ExtCtrls, DCPcrypt2, DCPblockciphers, DCPrijndael,
  DCPsha512, registry, ShlObj, SPGetSid;

const
  FDisk = 'C';

type
  Tkeys = class(TForm)
    EdtCertValidToS1: TEdit;
    btn1: TButton;
    DCP_sha5121: TDCP_sha512;
    DCP_rijndael1: TDCP_rijndael;
    tmr1: TTimer;
    procedure btn1Click(Sender: TObject);
    procedure EdtCertValidToS1KeyPress(Sender: TObject; var Key: Char);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormActivate(Sender: TObject);
    procedure tmr1Timer(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
    crc:string;
    ks: Integer;
    function GetDiskSerial: string;
  end;

var
  keys: Tkeys;
  SerialNum,dtyp:DWORD;
  sn,ds:string;

implementation

{$R *.dfm}

uses acRW, clipbrd, tor;

function DigestToStr(Digest: array of byte): string;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to 19 do
    Result := Result + LowerCase(IntToHex(Digest[i], 2));
end;

function Getsha512FromString(Source: string): string;
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

//Привязка к железу
function GetCompName: string;
var
 buffer: array[0..255] of char;
 size: dword;
begin
 size := 256;
 if GetComputerName(buffer, size) then
   Result := buffer
 else
   Result := ''
end;

//Узнать номер диска
function GetHDDSerialNumber(ADisk: char): String;
var
  SerialNum           : dword;
  VolumeName, FSName  : array [0..255] of char;
  MaximumFNameLength,
  FileSystemFlags     : dword;
begin
   Result := '';
   if GetVolumeInformation( PChar( ADisk + ':\' ),
                            VolumeName, SizeOf( VolumeName ),
                            @SerialNum,
                            MaximumFNameLength,
                            FileSystemFlags,
                            FSName, SizeOf( FSName ) ) then
   Result := Format( '%.8x', [SerialNum] );
end;

//Тип проца
function ProcType: string;
var
 lpSystemInfo : TSystemInfo;
begin
 GetSystemInfo(lpSystemInfo);
 Result:=IntToStr(lpSystemInfo.dwProcessorType);
end;

//количество памяти
function MemorySize: string;
var
 lpMemoryStatus : TMemoryStatus;
begin
    lpMemoryStatus.dwLength := SizeOf(lpMemoryStatus);
    GlobalMemoryStatus(lpMemoryStatus);
with lpMemoryStatus do begin
     Result:=Format('%0.0f',[dwTotalPhys div 1024 / 1024])+' Mb';
end;
end;

function Tkeys.GetDiskSerial: string;
var
  VN: array[0..255] of char;
  SN, VW, SW: DWORD;                      
begin
  GetVolumeInformation(PChar(FDisk + ':\'), VN, SizeOf(VN), @SN, VW, SW, nil, 0);
  Result := Getsha512FromString(IntToStr(SN));
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

//Для зашифрования строки
function EncryptString(Source, Password: string): string;
var
  DCP_rijndael1: TDCP_rijndael;
begin
  DCP_rijndael1 := TDCP_rijndael.Create(nil);   // создаём объект
  DCP_rijndael1.InitStr(Password, TDCP_sha512);    // инициализируем
  Result := DCP_rijndael1.EncryptString(Source); // шифруем
  DCP_rijndael1.Burn;                            // стираем инфо о ключе
  DCP_rijndael1.Free;                            // уничтожаем объект
end;

//Для расшифрования строки
function DecryptString(Source, Password: string): string;
var
  DCP_rijndael1: TDCP_rijndael;
begin
  DCP_rijndael1 := TDCP_rijndael.Create(nil);   // создаём объект
  DCP_rijndael1.InitStr(Password, TDCP_sha512);    // инициализируем
  Result := DCP_rijndael1.DecryptString(Source); // дешифруем
  DCP_rijndael1.Burn;                            // стираем инфо о ключе
  DCP_rijndael1.Free;                            // уничтожаем объект
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

//использовать:
//label1.Caption := GetNormalSize(GetFileSize(Filename));
function GetFileSize(namefile: string): Int64; 
var 
InfoFile: TSearchRec; 
AttrFile: Integer; 
ErrorReturn: Integer; 
begin 
AttrFile := $0000003F; // Any file 
ErrorReturn := FindFirst(namefile, AttrFile, InfoFile); 
if ErrorReturn <> 0 then 
Result := -1 // в случае, если файл не найден 
else 
begin 
Result := InfoFile.FindData.nFileSizeHigh; // Размер файла в байтах 
Result := Result shl 32; 
Result := Result or InfoFile.FindData.nFileSizeLow; 
end; 
FindClose(InfoFile); 
end;

{$WARNINGS ON}

function GetNormalSize(Size: Int64): string; 
var 
kb, Mb, Gb: Real; 
begin 
Result := IntToStr(Size) + ' b'; 
kb := Size / 1024; 
kb := Trunc(kb * 10) / 10; 
if kb < 0.7 then 
Exit; 
Result := FloatToStr(kb) + ' kb'; 
Mb := kb / 1024; 
Mb := Trunc(Mb * 10) / 10; 
if Mb < 0.7 then 
Exit; 
Result := FloatToStr(Mb) + ' Mb'; 
Gb := Mb / 1024; 
Gb := Trunc(Gb * 10) / 10; 
if Gb < 0.7 then 
Exit; 
Result := FloatToStr(Gb) + ' Gb'; 
end;

procedure Tkeys.btn1Click(Sender: TObject);
var
 k: TStringList;
 a,b:DWORD;
 ds,sn,si,sn1,fs:string;
 Buffer :Array[0..255]of char;
begin
  //========================================
   ExpandEnvironmentStrings(PChar('%systemdrive%'),Buffer,SizeOf(Buffer));
   ds:=Buffer;
   ds:=GetHDDSerialNumber(ds[1]);
   dtyp:=GetDriveType('c:/');
   dtyp := DRIVE_REMOVABLE;
   GetVolumeInformation('c:/',Buffer,sizeof(Buffer),@SerialNum,a,b,nil,0);
   sn:=IntToStr(SerialNum);
   si:=GetCurrentUserSid;
   sn1 := GetDiskSerial;
  //========================================
   crc:=sn+'-'+ds+'-'+si+'-'+MemorySize+'-'+ProcType+'-'+GetCompName+'-'+sn1;
  //========================================
   if crc <> EdtCertValidToS1.Text then Application.Terminate else begin
   if FileExists(ExtractFilePath(ParamStr(0))+'lic.sts') then
    begin
      fs:=GetNormalSize(GetFileSize(ExtractFilePath(ParamStr(0))+'lic.sts'));
      if fs = '0 b' then begin
         DeleteFile(ExtractFilePath(ParamStr(0))+'lic.sts');
         Exit;
      end;
      crc:=AppendedStringFromFile(ExtractFilePath(ParamStr(0))+'lic.sts');
      crc:=DecryptString(crc,KeyRelease);
      MyStream := TFilestream.Create(ExtractFilePath(ParamStr(0))+'lic.sts',fmOpenRead or fmShareExclusive);
  ///////////Добавляем отображаемую иконку/////////////
      reg := tregistry.create;
     // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    // создается ключ ".blowfish", если его нет
      reg.openkey('.sts',true);
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!sts');
    // закрываем этот ключ
      reg.openkey('!sts\defaulticon',true);
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.openkey('!sts\shell\open\command', true);
      //reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
      keys.Close;
    end else
    begin
     //создание объекта для записи в файл drive
     k:= TStringList.Create;
     //запись в файл
     k.SaveToFile(ExtractFilePath(ParamStr(0))+'lic.sts');
     k.Free;
     crc:=EncryptString(crc,KeyRelease);
    //запись в файл
     AppendStringToFile(ExtractFilePath(ParamStr(0))+'lic.sts',crc);
     MyStream := TFilestream.Create(ExtractFilePath(ParamStr(0))+'lic.sts',fmOpenRead or fmShareExclusive);
  ///////////Добавляем отображаемую иконку/////////////
      reg := tregistry.create;
     // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    // создается ключ ".blowfish", если его нет
      reg.openkey('.sts',true);
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!sts');
    // закрываем этот ключ
      reg.openkey('!sts\defaulticon',true);
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.openkey('!sts\shell\open\command', true);
      //reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
     keys.Close;
    end;
   end;
end;

procedure Tkeys.EdtCertValidToS1KeyPress(Sender: TObject; var Key: Char);
begin
if not (Key in ['0'..'9', #8])then Key:=#0;
end;

procedure Tkeys.FormCreate(Sender: TObject);
var
 fs:string;
begin
  //=====Защита от отладчика===========
  if DebuggerPresent then Application.Terminate;
  if FileExists(ExtractFilePath(ParamStr(0))+'lic.sts') then
   begin
     fs:=GetNormalSize(GetFileSize(ExtractFilePath(ParamStr(0))+'lic.sts'));
     if fs = '0 b' then begin
        DeleteFile(ExtractFilePath(ParamStr(0))+'lic.sts');
        Exit;
     end;
     crc:=AppendedStringFromFile(ExtractFilePath(ParamStr(0))+'lic.sts');
     crc:=DecryptString(crc,KeyRelease);
     MyStream := TFilestream.Create(ExtractFilePath(ParamStr(0))+'lic.sts',fmOpenRead or fmShareExclusive);
  ///////////Добавляем отображаемую иконку/////////////
      reg := tregistry.create;
     // устанавливаем главный раздел
      reg.rootkey := HKEY_CLASSES_ROOT;
    // создается ключ ".blowfish", если его нет
      reg.openkey('.sts',true);
    // создается параметр со значением "!txt", если его нет
      reg.writestring('', '!sts');
    // закрываем этот ключ
      reg.openkey('!sts\defaulticon',true);
      reg.writestring('', paramstr(0) + ', 1');
      reg.closekey;
      reg.openkey('!sts\shell\open\command', true);
      reg.writestring('', Application.ExeName+' %1'); //Вот, вместо пути, меняем на свой.
    // закрываем ключ
      reg.closekey;
    // освобождаем реестр, но настройки сохраняем
      reg.free;
      SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nil, nil);
  ////////////////////////////////////////////////////////////////
      keys.Close;
   end else keys.ShowModal;
end;

procedure Tkeys.FormDestroy(Sender: TObject);
begin
  if crc = '' then Application.Terminate;
end;

procedure Tkeys.FormActivate(Sender: TObject);
begin
with keys do
     SetWindowPos(Handle,
     HWND_TOPMOST,
     Left,
     Top,
     Width,
     Height,
     SWP_NOACTIVATE or SWP_NOMOVE or SWP_NOSIZE);
end;

procedure Tkeys.tmr1Timer(Sender: TObject);
begin
  if DebuggerPresent then Application.Terminate;
end;

end.
