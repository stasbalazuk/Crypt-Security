program crypt;

uses
  Forms,
  key in 'key.pas' {keys},
  tor in 'tor.pas' {CRF},
  pw in 'pw.pas' {myps},
  infcrypt in 'infcrypt.pas' {infc},
  edit in 'edit.pas' {edt};

{$R *.res}

label vx;
var
  CompaInf: Tinfc;

begin
   Application.Initialize;
   Application.CreateForm(Tkeys, keys);    
   Application.Title := '© StalkerSTS Corporation.  All rights reserved.';
  try
    CompaInf := Tinfc.Create(nil);
    CompaInf.Caption := 'StelS - Защита программы S@S';
    CompaInf.ShowModal;
  except
    Exit;
  end;
  if keys.ks = 0 then goto vx
  else begin
    Application.CreateForm(TCRF, CRF);
    Application.CreateForm(Tmyps, myps);
    Application.CreateForm(Tedt, edt);
    Application.ShowMainForm:=False;
    Application.Run;
  end;
  vx:
end.
