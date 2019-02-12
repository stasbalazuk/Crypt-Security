unit edit;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls;

type
  Tedt = class(TForm)
    mmo1: TMemo;
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  edt: Tedt;

implementation

uses tor, ClipBrd, pw;

{$R *.dfm}

procedure Tedt.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  mmo1.Lines.SaveToFile(ExtractFilePath(ParamStr(0))+'mypass.ini');
end;

end.
