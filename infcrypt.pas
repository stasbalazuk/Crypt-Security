unit infcrypt;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, jpeg, ExtCtrls, StdCtrls, ComCtrls;

type
  Tinfc = class(TForm)
    img1: TImage;
    lbledt1: TLabeledEdit;
    lbl1: TLabel;
    tmr1: TTimer;
    procedure img1Click(Sender: TObject);
    procedure lbledt1KeyPress(Sender: TObject; var Key: Char);
    procedure FormActivate(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

  TKeyPass = class
  private
    function password : string;
  public
    constructor create;
    destructor destroy; override;
  end;

var
  infc: Tinfc;
  sk: string;

implementation

uses key;

{$R *.dfm}

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

procedure Tinfc.img1Click(Sender: TObject);
begin
  lbledt1.EditLabel.Caption:='Введите пароль:';
end;

procedure Tinfc.lbledt1KeyPress(Sender: TObject; var Key: Char);
begin
  if Key = #13 then begin
  if lbledt1.Text <> sk then begin
     keys.ks:=0;
     lbledt1.EditLabel.Caption:='Неверный пароль';
     lbledt1.Text:='';
     Application.Terminate;
  end else begin
     keys.ks:=1;
     lbledt1.EditLabel.Caption:='Введите пароль:';
     lbledt1.Text:='';
     Close;
     Exit;
  end;
  end;
end;

procedure Tinfc.FormActivate(Sender: TObject);
var
  s: TKeyPass;
begin
  keys.ks:=0;
  s:=TKeyPass.create;
  sk:=s.password;
  lbl1.Caption:='Версия: '+ShowVersion(Application.ExeName);
end;

{ TKeyPass }

constructor TKeyPass.create;
begin
  if DebuggerPresent then Application.Terminate;
end;

destructor TKeyPass.destroy;
begin
  destroy;
end;

function TKeyPass.password: string;
const
    Mes: array[1..12] of string = ('01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12');
var
  i:integer;
  d,m,y: string;
  Year, Month, Day: Word;
begin
  DecodeDate(Now,Year,Month,Day);
  d := IntToStr(day);
  m := Mes[Month];
  y := IntToStr(Year);
  i:=StrToInt(d)+StrToInt(m);
  i:=i+StrToInt(m);
  i:=StrToInt(y)+i;
  Result:=IntToStr(i);
end;

procedure Tinfc.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  if DebuggerPresent then Application.Terminate;
  if (lbledt1.Text <> sk) and (keys.ks = 0) then begin
     keys.ks:=0;
     lbledt1.EditLabel.Caption:='Неверный пароль';
     lbledt1.Text:='';
     Application.Terminate;
  end else begin
     keys.ks:=1;
     lbledt1.EditLabel.Caption:='Введите пароль:';
     lbledt1.Text:='';
     Close;
     Exit;
  end;
end;

end.
