unit pass;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, XPMan;

type
  TPS = class(TForm)
    GroupBox1: TGroupBox;
    password: TEdit;
    btn1: TButton;
    procedure passwordKeyPress(Sender: TObject; var Key: Char);
    procedure btn1Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormActivate(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  PS: TPS;
  ExB,i,i1,i2,i3,i4,i5:integer;

implementation

uses FileCript;

{$R *.dfm}

procedure TPS.passwordKeyPress(Sender: TObject; var Key: Char);
begin
if not (Key in ['0'..'9', #8])then Key:=#0;
end;

procedure TPS.btn1Click(Sender: TObject);
begin
if password.Text <> '' then
 begin
  i:=StrToInt(copy(DateToStr(Date),1,2));
  i1:=StrToInt(copy(DateToStr(Date),4,2));
  i2:=StrToInt(copy(DateToStr(Date),7,4));
  i3:=i+i1;
  i4:=i1+i3;
  i5:=i2+i4;
  ExB:=i5;
 if Exb=StrToInt(password.Text) then
  begin
    password.Clear;
    PS.Caption:='Пароль верный!';
    PS.Tag := 0;
    PS.Close;
  end else
  begin
    password.Clear;
    PS.Caption:='Пароль не верный!';
    PS.Tag := 1;
    PS.Close;
  end;
 end;
end;

procedure TPS.FormCreate(Sender: TObject);
begin
  PS.Tag := 1;
end;

procedure TPS.FormActivate(Sender: TObject);
begin
with PS do
     SetWindowPos(Handle,
     HWND_TOPMOST,
     Left,
     Top,
     Width,
     Height,
     SWP_NOACTIVATE or SWP_NOMOVE or SWP_NOSIZE);
end;

end.
