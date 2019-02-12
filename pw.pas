unit pw;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, ComCtrls, IniFiles, StdCtrls, XPMan, ExtCtrls, Buttons,
  DCPcrypt2, DCPblockciphers, DCPrijndael, ddeman, DCPsha512,
  GetUrlBrowser,
  tlhelp32,
  ShellAPI;

type
  Tmyps = class(TForm)
    Button1: TButton;
    Button2: TButton;
    stat1: TStatusBar;
    cbb1: TComboBox;
    login: TLabeledEdit;
    ps: TLabeledEdit;
    lbl1: TLabel;
    sayt: TEdit;
    btn1: TSpeedButton;
    btn2: TSpeedButton;
    btn: TButton;
    DCP_sha5121: TDCP_sha512;
    DCP_rijndael1: TDCP_rijndael;
    tmr1: TTimer;
    btn3: TSpeedButton;
    btn4: TSpeedButton;
    dblInputFileSize1: TLabel;
    em: TEdit;
    btn5: TSpeedButton;
    chk1: TCheckBox;
    chk2: TCheckBox;
    procedure Button1Click(Sender: TObject);
    procedure Button2Click(Sender: TObject);
    procedure cbb1Change(Sender: TObject);
    procedure FormActivate(Sender: TObject);
    procedure btn1Click(Sender: TObject);
    procedure btn2Click(Sender: TObject);
    procedure btnClick(Sender: TObject);
    procedure tmr1Timer(Sender: TObject);
    procedure btn3Click(Sender: TObject);
    procedure btn4Click(Sender: TObject);
    procedure btn5Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure FormDestroy(Sender: TObject);
    procedure cbb1Click(Sender: TObject);
    procedure chk1Click(Sender: TObject);
    procedure chk2Click(Sender: TObject);
  private
    procedure WMEndSession(var Msg: TWMEndSession); message WM_ENDSESSION;
  public
    MyPict: PChar;
    MyHandle: THandle;
  end;

  function GetChromeActiveTabURL(Wnd: HWnd; Param: LParam): Bool; stdcall;

var
  myps: Tmyps;
  i,y: integer;
  s,s1,s2,s3,s4: string;
  p : TStringList;
  Ini : TIniFile;
  KeyRelease:string = 'dj4lgmnitG4gggfdASEg45g4g3j7rK620N2YZYiX4 DT]'+
                      '5rf7S/kMNm,n./OK/ilUN..u8h.H6fJFCj5DFNY6GMvbm,6FmTFMy6FMtfMy5fdN564BtErb'+
                      '7gl7G,ubKTRF645djDRJ5Dmy76l8h;9J;9J;8hfUFCGcgD4f4SHxnYhb,nvnvchgFH5RUrfO'+
                      'dskjhfpqo9s97hgBL7BL7bl7ghl7hGL87GLGl7l7glxdrgfcg58KHJghdfdrpPnbU'+
                      'DJFDKSFghjyg;KH9bn6CRTXCx4hUGLB.8.nkVTJ6FJfjylk7gl7GLUHm'+
                      'HG7gnkBk8jhKkKJHK87HkjkFGF6PCbV9KaK81WWYgP[CR[yjILWv2_SBE]AsLEz_8sBZ3LV5N'+
                      'Go0NLL1om4 XbALjhgkk7sda823r23;d923NrUdkzPp5 DkJ2_8JvYmWFn LR3CRxyfswsto'+
                      'cvnkscv78h2lk8HHKhlkjdfvsd;vlkvsd0vvds;ldvhyB[NXzl5y5Z';

implementation

{$R *.dfm}

uses ClipBrd, mshtml, ActiveX, COMObj, IdHTTP, idURI, RegExpr, tor, edit;     //, stsp


procedure Tmyps.WMEndSession(var Msg: TWMEndSession);
begin
  if Msg.EndSession = True then
   begin
    Application.Terminate;
    inherited;
   end;
end;

function CheckAllowed(const s: string): boolean;
var
    i: integer;
begin
    Result:= false;
    for i:= 1 to Length(s) do
    begin
      if not (s[i] in ['a'..'z', 'A'..'Z', '0'..'9', '_', '-', '.']) then
        Exit;
    end;
    Result:= true;
end;
 
function IsValidEmail(const Value: string): boolean;
var
  i: integer;
  namePart, serverPart: string;
begin
  Result:= false;
  i:= Pos('@', Value);
  if i = 0 then
    Exit;
  namePart:= Copy(Value, 1, i - 1);
  serverPart:= Copy(Value, i + 1, Length(Value));
  if (Length(namePart) = 0) or ((Length(serverPart) < 5)) then
    Exit;
  i:= Pos('.', serverPart);
  if (i = 0) or (i > (Length(serverPart) - 2)) then
    Exit;
  Result:= CheckAllowed(namePart) and CheckAllowed(serverPart);
end;

procedure CreateFormInRightBottomCorner;
var
 r : TRect;
begin
 SystemParametersInfo(SPI_GETWORKAREA, 0, Addr(r), 0);
 myps.Left := r.Right-myps.Width;
 myps.Top := r.Bottom-myps.Height;
end;

function GetChromeURL(hChrome: hwnd): string;
var w:hwnd; s:array[0..255] of char;
begin
 Result:='';FillChar(s,256,#0);
 w:=FindWindowEx(hChrome, 0, 'Chrome_AutocompleteEditView', nil);
 if Iswindow(w) then begin
   GetWindowText(w,@s[0],256);
   Result := s;
 end;
end;

function GetChromeActiveTabURL(Wnd: HWnd; Param: LParam): Bool; stdcall;
var
  urls: TStrings;
  hWndMainWindow, hWndTab: HWND;
  Buffer : array[0..255] of Char;
  res : boolean;
begin
  res := true;
  urls := TStrings(Param);
  SendMessage(Wnd, WM_GETTEXT, Length(Buffer), integer(@Buffer[0]));
  hWndMainWindow := FindWindow('Chrome_WidgetWin_1', Buffer);
  application.ProcessMessages;
  if hWndMainWindow <> 0 then
  begin
    hWndTab := FindWindowEx(hWndMainWindow, 0, 'Chrome_RenderWidgetHostHWND', nil);    //Chrome_AutocompleteEditView
    if hWndTab <> 0 then
    begin
      SendMessage(hWndTab, WM_GETTEXT, Length(Buffer), integer(@Buffer));
      urls.Add(Buffer);
      res := false;
    end;
  end;
  Result := res;
end;

function GetActivePageUrlFromChrome(Handle: HWnd; Param: LParam): Bool; stdcall;
var
 List: TStrings;
 hWndChrome, hWndChromeChild: HWND;
 Buffer            : array[0..255] of Char;
begin
 List := TStrings(Param);
 //get the window caption
 SendMessage(Handle, WM_GETTEXT, Length(Buffer), integer(@Buffer[0]));
 //look for the chrome window with "Buffer" caption
 hWndChrome := FindWindow('Chrome_WidgetWin_1', Buffer);
 if hWndChrome <> 0 then
 begin
   hWndChromeChild := FindWindowEx(hWndChrome, 0, 'Chrome_RenderWidgetHostHWND', nil);
   if hWndChromeChild <> 0 then
   begin
     SendMessage(hWndChromeChild, WM_GETTEXT, Length(Buffer), integer(@Buffer));
     List.Add(Buffer);
   end;
 end;
 Result := True;
end;

function GetActiveUrl: string;
var
 Client_DDE: TDDEClientConv;
 temp: PAnsiChar;
 res,s:string;
 i: integer;
 lst: TStringList;
begin
 Result:='';
 lst:= TStringList.Create;
 lst.Add('Opera');
 lst.Add('Google Chrome');
 lst.Add('IExplore');
 lst.Add('Mozilla');
 lst.Add('Firefox');
 for i:=0 to lst.Count-1 do begin
 s:=lst.Strings[i];
 Client_DDE:= TDDEClientConv.Create( nil );
 with Client_DDE do
  begin
   SetLink(s, 'WWW_GetWindowInfo');
   temp := RequestData('0xFFFFFFFF');
   Res := StrPas(temp);
  // Return only the URL part
   Delete(Res, Pos(',', Res), Length(Res)-Pos(',', Res)+1);
   // Remove quotes
   Delete(Res, 1, 1);
   Delete(Res, Length(Res), 1);
   // ************
   StrDispose(temp);
   CloseLink;
  end;
 Client_DDE.Free;
 if Res='' then Res:='---';
 if Res <> '---' then Result:=res;
 end;
 lst.Free;
end;

function EnumMainWindowProc(Handle: HWnd; LParam: LParam): boolean; stdcall;
var
  lpClassName: PChar;
  intList: TList;
  nd: Pointer;
begin
  intList := TList(LParam);
  GetMem(lpClassName, 255);
  try
    FillChar(lpClassName^, 255, 0);
    if (GetClassName(Handle, lpClassName, 255) > 0)and
      (lpClassName = 'Chrome_WidgetWin_0') then
        intList.Add(nd);
  finally
    FreeMem(lpClassName);
  end;
  Result := true;
end;

procedure ExtractLinks(const url: String; const strings: TStrings) ;
var
   iDoc : IHTMLDocument2;
   strHTML : string;
   v : Variant;
   x : integer;
   links : OleVariant;
   docURL : string;
   URI : TidURI;
   aHref : string;
   idHTTP : TidHTTP;
begin
  strings.Clear;
  URI := TidURI.Create(url) ;
   try
    docURL := 'http://' + URI.Host;
     if URI.Path <> '/'  then docURL := docURL + URI.Path;
   finally
    URI.Free;
   end;
  iDoc := CreateComObject(Class_HTMLDOcument)  as IHTMLDocument2;
   try
    iDoc.designMode := 'on';
     while iDoc.readyState <> 'complete'  do Application.ProcessMessages;
    v := VarArrayCreate([0,0],VarVariant) ;
    idHTTP := TidHTTP.Create(nil) ;
     try
      strHTML := idHTTP.Get(url) ;
     finally
      idHTTP.Free;
     end;
    v[0]:= strHTML;
    iDoc.write(PSafeArray(System.TVarData(v).VArray)) ;
    iDoc.designMode := 'off';
     while iDoc.readyState<>'complete'  do Application.ProcessMessages;
    links := iDoc.all.tags('A') ;
     if links.Length > 0  then
     begin
       for x := 0  to -1 + links.Length  do
       begin
        aHref := links.Item(x).href;
         if (aHref[1] = '/')  then
          aHref := docURL + aHref
         else if Pos('about:', aHref) = 1
          then aHref := docURL + Copy(aHref, 7, Length(aHref)) ;
        strings.Add(aHref) ;
       end;
     end;
   finally
    iDoc :=  nil;
   end;
end;

function ExtractURL(const AInputString : string) : string;
const
 URLTemplate =
  '(?i)' 
  + '(' 
  + '(HTTP)://'
  + '|www\.)'
  + '([\w\d\-]+(\.[\w\d\-]+)+)'
  + '(:\d\d?\d?\d?\d?)?'
  + '(((/[%+\w\d\-\\\.]*)+)*)'
  + '(\?[^\s=&]+=[^\s=&]+(&[^\s=&]+=[^\s=&]+)*)?'
  + '(#[\w\d\-%+]+)?';
var
 r : TRegExpr;
begin
 Result := '';
 r := TRegExpr.Create;
 try
    r.Expression := URLTemplate;
    if r.Exec (AInputString) then
     REPEAT
     Result := Result + r.Match [0] + ',';
     UNTIL not r.ExecNext;
   finally r.Free;
  end;
end;

function strtst(var Input: string; EArray: string; Action: integer): string;
begin
  case Action of
    1:
      begin
        while length(Input) <> 0 do
        begin
          if pos(Input[1], EArray) = 0 then
            delete(Input, 1, 1)
          else
          begin
            result := result + Input[1];
            delete(Input, 1, 1);
          end;
        end;
      end;
    2:
      begin
        while length(Input) <> 0 do
        begin
          if pos(Input[1], EArray) <> 0 then
            delete(Input, 1, 1)
          else
          begin
            result := result + Input[1];
            delete(Input, 1, 1);
          end;
        end;
      end;
  else
    messagebox(0, 'Не корректный вызов функции.', '', mb_ok);
  end;
end;

//Перехват адреса в браузере
function Get_URL(Servicio: string): String;
var
   Cliente_DDE: TDDEClientConv;
   temp:PChar;      //<<-------------------------This is new
begin
    Result := '';
    Cliente_DDE:= TDDEClientConv.Create( nil );
     with Cliente_DDE do
        begin
           SetLink( Servicio,'WWW_GetWindowInfo');
           temp := RequestData('0xFFFFFFFF');
           Result := StrPas(temp);
           StrDispose(temp);
           CloseLink;
        end;
      Cliente_DDE.Free;
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

//Файл без расширения
function ExtractOnlyFileName(const FileName: string): string;
begin
  result:=StringReplace(ExtractFileName(FileName),ExtractFileExt(FileName),'',[]);
end;

procedure StrToClipbrd(StrValue: string);
var
 hMem: THandle;
 pMem: PChar;
begin
 hMem := GlobalAlloc(GHND or GMEM_SHARE, Length(StrValue) + 1);
if hMem <> 0 then
 begin
   pMem := GlobalLock(hMem);
   if pMem <> nil then
    begin
      StrPCopy(pMem, StrValue);
      GlobalUnlock(hMem);
    if OpenClipboard(0) then
     begin
       EmptyClipboard;
       SetClipboardData(CF_TEXT, hMem);
       CloseClipboard;
     end
    else
       GlobalFree(hMem);
   end else GlobalFree(hMem);
end;
end;

function GetStrFromClipbrd: string;
begin
if Clipboard.HasFormat(CF_TEXT) then begin
   Result := Clipboard.AsText;
   myps.stat1.Panels[1].Text:='Пароль скопирован в буфер!'; end
else begin
   myps.stat1.Panels[1].Text:='Пароль не скопирован в буфер!';
   Result := '';
end;
end;

procedure Tmyps.Button1Click(Sender: TObject);
begin
 if sayt.Text = '' then Exit;
 if not IsValidEmail(em.Text) then begin
    MessageBox(Handle,PChar('E-mail - введен неправильно!'),PChar('Внимание'),64);
    Exit;
 end;
 if FileExists(ExtractFilePath(ParamStr(0))+'mypass.ini.Rij') then
  begin
    s:=ExtractFilePath(ParamStr(0))+''+ExtractOnlyFileName(ExtractFilePath(ParamStr(0))+'mypass.ini.Rij');
    DecryptFile(ExtractFilePath(ParamStr(0))+'mypass.ini.Rij',s,KeyRelease);
  if sayt.Text <> '' then
   begin
 if FileExists(ExtractFilePath(ParamStr(0))+'mypass.ini') then
  begin
    Ini:= TIniFile.Create(ExtractFilePath(ParamStr(0))+'mypass.ini');
    if Ini.ReadString('PASS',sayt.Text,'') <> sayt.Text then
       s:=Ini.ReadString('PASS',sayt.Text,'');
       s1:=Ini.ReadString('PASS',ps.Text,'');
       s2:=Ini.ReadString('PASS',login.Text,'');
       s3:=Ini.ReadString('PASS',em.Text,'');
    Ini.Free;
    if (s = sayt.Text) and
       (s1 = ps.Text) and
       (s2 = login.Text) and
       (s3 = em.Text) then
     begin
       stat1.Panels[1].Text:=sayt.Text+' - уже есть в файле!';
       exit;
     end else
     begin
       StrToClipbrd(ps.Text);
       stat1.Panels[1].Text:='Пароль '+ps.Text+' в буфере!';
       login.Text:='$'+EncryptString(login.Text,KeyRelease);
       ps.Text:='$'+EncryptString(ps.Text,KeyRelease);
       em.Text:='$'+EncryptString(em.Text,KeyRelease);
       Ini:= TIniFile.Create(ExtractFilePath(ParamStr(0))+'mypass.ini');
       Ini.WriteString('PASS',sayt.Text,'$'+login.Text+'$'+ps.Text+'$'+em.Text);
       Ini.Free;
       login.Enabled:=False;
       sayt.Enabled:=False;
       ps.Enabled:=False;
       em.Enabled:=False;
       cbb1.Items.LoadFromFile(ExtractFilePath(ParamStr(0))+'mypass.ini');
     if s <> '[PASS]' then cbb1.Items.Delete(0);
     if FileExists(ExtractFilePath(ParamStr(0))+'mypass.ini') then
      begin
       EncryptFile(ExtractFilePath(ParamStr(0))+'mypass.ini',ExtractFilePath(ParamStr(0))+'mypass.ini.Rij',KeyRelease);
       DeleteFile(ExtractFilePath(ParamStr(0))+'mypass.ini');
      end;
     end;
  end;
    if FileExists(ExtractFilePath(ParamStr(0))+'mypass.ini') then
     begin
       EncryptFile(ExtractFilePath(ParamStr(0))+'mypass.ini',ExtractFilePath(ParamStr(0))+'mypass.ini.Rij',KeyRelease);
       DeleteFile(ExtractFilePath(ParamStr(0))+'mypass.ini');
     end;
   end;
  end else begin
       StrToClipbrd(ps.Text);
       stat1.Panels[1].Text:='Пароль '+ps.Text+' в буфере!';
       login.Text:='$'+EncryptString(login.Text,KeyRelease);
       ps.Text:='$'+EncryptString(ps.Text,KeyRelease);
       em.Text:='$'+EncryptString(em.Text,KeyRelease);
       Ini:= TIniFile.Create(ExtractFilePath(ParamStr(0))+'mypass.ini');
       Ini.WriteString('PASS',sayt.Text,'$'+login.Text+'$'+ps.Text+'$'+em.Text);
       Ini.Free;
       login.Enabled:=False;
       sayt.Enabled:=False;
       ps.Enabled:=False;
       em.Enabled:=False;
       cbb1.Items.LoadFromFile(ExtractFilePath(ParamStr(0))+'mypass.ini');
    if FileExists(ExtractFilePath(ParamStr(0))+'mypass.ini') then
     begin
       EncryptFile(ExtractFilePath(ParamStr(0))+'mypass.ini',ExtractFilePath(ParamStr(0))+'mypass.ini.Rij',KeyRelease);
       DeleteFile(ExtractFilePath(ParamStr(0))+'mypass.ini');
     end;
  end;
  Button1.Tag:=1;
  tmr1.Enabled:=True;
end;

procedure Tmyps.Button2Click(Sender: TObject);
begin
  if Button1.Tag = 1 then begin
     login.Clear;
     sayt.Clear;
     ps.Clear;
     em.Clear;
     stat1.Panels[1].Text:='Выберите данные для расшифровки!';
     Button1.Tag := 0;
     Exit;
  end;
  if login.Text <> '' then
     login.Text:=DecryptString(login.Text,KeyRelease);
  if ps.Text <> '' then
     ps.Text:=DecryptString(ps.Text,KeyRelease);
  if em.Text <> 'e-mail@mail.ru' then begin
     em.Text:=DecryptString(em.Text,KeyRelease);
     stat1.Panels[1].Text:='Данные расшифрованы!';
  end;
  Button2.Tag:=1;
  login.Enabled:=True;
  sayt.Enabled:=True;
  ps.Enabled:=True;
  em.Enabled:=True;
  if Button2.Tag <> 0 then begin
  btn1.Enabled:=True;
  btn2.Enabled:=True;
  btn3.Enabled:=True;
  btn4.Enabled:=True;
  btn5.Enabled:=True;
  Button2.Tag:=0;
  end else begin
  btn1.Enabled:=False;
  btn2.Enabled:=False;
  btn3.Enabled:=False;
  btn4.Enabled:=False;
  btn5.Enabled:=False;
  end;
end;

procedure Tmyps.cbb1Change(Sender: TObject);
begin
  tmr1.Enabled:=False;
  s:=cbb1.Items.Strings[cbb1.ItemIndex];
  p:=TStringList.Create;
  ExtractStrings(['$'],['$'],PChar(s),p);
  if p.Count > 0 then
    s1:=p[0];
  if p.Count > 1 then
    s2:=p[1];
  if p.Count > 2 then
    s3:=p[2];
  if p.Count > 3 then
    s4:=p[3];
  p.Free;
  login.Text:=s2;
  sayt.Text:=s1;
  ps.Text:=s3;
  em.Text:=s4;
  login.Enabled:=False;
  sayt.Enabled:=False;
  ps.Enabled:=False;
  em.Enabled:=False;
  tmr1.Enabled:=False;
  if cbb1.Text <> '' then begin
  tmr1.Enabled:=True;
  end;
  btn1.Enabled:=True;
  btn2.Enabled:=True;
  btn3.Enabled:=True;
  btn4.Enabled:=True;
  btn5.Enabled:=True;  
end;

procedure Tmyps.FormActivate(Sender: TObject);
begin
// снимаем блокировку области памяти занятую Clipboard-ом
GlobalUnlock(MyHandle);
// закрываем Clipboard
Clipboard.Close;
//////////////
myps.Tag:=10;
CreateFormInRightBottomCorner;
cbb1.Items.Delete(0);
login.Enabled:=False;
sayt.Enabled:=False;
ps.Enabled:=False;
em.Enabled:=False;
if FileExists(ExtractFilePath(ParamStr(0))+'mypass.ini.Rij') then begin
   s:=ExtractFilePath(ParamStr(0))+ExtractOnlyFileName(ExtractFilePath(ParamStr(0))+'mypass.ini.Rij');
   DecryptFile(ExtractFilePath(ParamStr(0))+'mypass.ini.Rij',s,KeyRelease);
 if FileExists(ExtractFilePath(ParamStr(0))+'mypass.ini') then
  begin
    cbb1.Items.LoadFromFile(ExtractFilePath(ParamStr(0))+'mypass.ini');
  for i:=0 to cbb1.Items.Count-1 do begin
    s:=cbb1.Items.Strings[i];
   if s = '[PASS]' then cbb1.Items.Delete(i);
    login.Text:=s3;
    sayt.Text:=s1;
    ps.Text:=s4;
  end;
   EncryptFile(ExtractFilePath(ParamStr(0))+'mypass.ini',ExtractFilePath(ParamStr(0))+'mypass.ini.Rij',KeyRelease);
   DeleteFile(ExtractFilePath(ParamStr(0))+'mypass.ini');
  end;
end;
//открываем Clipboard
 ClipBoard.Open;
// формируем указатель на пустой Clipboard формат CF_BITMAP
// а можно любой другой см. HELP
 MyHandle := Clipboard.GetAsHandle(CF_bitmap);
// блокируем область памяти занятую Clipboard-ом
 MYpict := GlobalLock(MyHandle);
end;

procedure Tmyps.btn1Click(Sender: TObject);
begin
  StrToClipbrd(DecryptString(login.Text,KeyRelease));
  stat1.Panels[1].Text:='Логин в буфере обмена!';
end;

procedure Tmyps.btn2Click(Sender: TObject);
begin
  StrToClipbrd(DecryptString(ps.Text,KeyRelease));
  stat1.Panels[1].Text:='Пароль в буфере обмена!';
end;

procedure Tmyps.btnClick(Sender: TObject);
begin
 if FileExists(ExtractFilePath(ParamStr(0))+'mypass.ini.Rij') then
  begin
      s:=ExtractFilePath(ParamStr(0))+ExtractOnlyFileName(ExtractFilePath(ParamStr(0))+'mypass.ini.Rij');
      DecryptFile(ExtractFilePath(ParamStr(0))+'mypass.ini.Rij',s,KeyRelease);
      s:=cbb1.Items.Strings[cbb1.ItemIndex];
      p:=TStringList.Create;
      ExtractStrings(['$'],['$'],PChar(s),p);
      if p.Count > 0 then
         s1:=p[0];
      if p.Count > 1 then
         s2:=p[1];
      if p.Count > 2 then
         s3:=p[2];
      if p.Count > 3 then
         s4:=p[3];
      p.Free;
     s1:=strtst(s1,'=',2);
     sayt.Text:=s1;
  if s1 <> '[PASS]' then begin
  if FileExists(ExtractFilePath(ParamStr(0))+'mypass.ini') then
  begin
    Ini:= TIniFile.Create(ExtractFilePath(ParamStr(0))+'mypass.ini');
    if Ini.ReadString('PASS',s1,'') <> '' then
       Ini.DeleteKey('PASS',s1);
       Ini.Free;
       stat1.Panels[1].Text:=sayt.text+' - удален!';
       cbb1.Items.LoadFromFile(ExtractFilePath(ParamStr(0))+'mypass.ini');
    if s1 <> '[PASS]' then cbb1.Items.Delete(0);   
    if s1 <> '[PASS]' then cbb1.Items.Delete(cbb1.ItemIndex);
  end;
  end;
  EncryptFile(ExtractFilePath(ParamStr(0))+'mypass.ini',ExtractFilePath(ParamStr(0))+'mypass.ini.Rij',KeyRelease);
  DeleteFile(ExtractFilePath(ParamStr(0))+'mypass.ini');
  end else stat1.Panels[1].Text:='НЕТ файла: mypass.ini.Rij';
end;

procedure Tmyps.tmr1Timer(Sender: TObject);
begin
 //=====Защита от отладчика===========
 if DebuggerPresent then Application.Terminate;
 if FileExists(ExtractFilePath(ParamStr(0))+'mypass.ini') then
  begin
    EncryptFile(ExtractFilePath(ParamStr(0))+'mypass.ini',ExtractFilePath(ParamStr(0))+'mypass.ini.Rij',KeyRelease);
    DeleteFile(ExtractFilePath(ParamStr(0))+'mypass.ini');
  end;
  myps.FormStyle:=fsStayOnTop;
with myps do
     SetWindowPos(Handle,
     HWND_TOPMOST,
     Left,
     Top,
     Width,
     Height,
     SWP_NOACTIVATE or SWP_NOMOVE or SWP_NOSIZE);
end;

procedure Tmyps.btn3Click(Sender: TObject);
var reg:TRegExpr;
    str:string;
    slChromeUrl      : TStringList;
begin
  if sayt.Text <> '' then begin
  ///////////////////////////////
  str:=sayt.Text; //загружаем твою страничку
  reg:=TRegExpr.Create;
  reg.Expression:='(http://)[^/]+';
  if reg.Exec(str) then
  Repeat
     str:=reg.Match[0]; //выводим результат
     stat1.Panels[1].Text:='Доступ к '+str+' получен!';
     sayt.Text:=str;
  Until not reg.ExecNext else stat1.Panels[1].Text:='Немогу получить доступ к '+str;
  reg.Free;
  ///////////////////////////////
  end else begin
  s:=Get_URL('firefox');
  sayt.Text:=ExtractURL(s);  
  ///////////////////////////////
  str:=s; //загружаем твою страничку
  reg:=TRegExpr.Create;
  reg.Expression:='(https://)[^/]+';
  if reg.Exec(str) then
  Repeat
     str:=reg.Match[0]; //выводим результат
     stat1.Panels[1].Text:='Доступ к '+str+' получен!';
     sayt.Text:=str;
  Until not reg.ExecNext else stat1.Panels[1].Text:='Немогу получить доступ '+str;
  reg.Free;
  ///////////////////////////////
  end;
  if s = '' then begin
     s:=GetActiveUrl;
  if s <> '' then Exit;
  end;
  if s = '' then begin
     s:=GetURL('Google Chrome');
  if s <> '' then Exit;
  end;
  slChromeUrl := TStringList.Create;
  try
    EnumWindows(@GetChromeActiveTabURL, LParam(slChromeUrl));
  if slChromeUrl.Count > 0 then
    sayt.Text:=slChromeUrl.Text;
    s1 := TIdURI.URLDecode(slChromeUrl.Text);
  finally
    FreeAndNil(slChromeUrl);
  end;
  /////////////////////////
end;

procedure Tmyps.btn4Click(Sender: TObject);
begin
     s:=sayt.Text;
     s:=strtst(s,'=',2);
  if s <> '' then begin
     ShellExecute(Handle, 'open', PChar(s), nil, nil, SW_NORMAL );
     stat1.Panels[1].Text:='Сайт открывается ...';
     tmr1.Enabled:=True;
  end;
end;

procedure Tmyps.btn5Click(Sender: TObject);
begin
  StrToClipbrd(DecryptString(em.Text,KeyRelease));
  stat1.Panels[1].Text:='E-mail в буфер обмена!';
end;

procedure Tmyps.FormCreate(Sender: TObject);
begin
 CreateFormInRightBottomCorner;
end;

procedure Tmyps.FormClose(Sender: TObject; var Action: TCloseAction);
begin
myps.Tag:=0;
tmr1.Enabled:=False;
// снимаем блокировку области памяти занятую Clipboard-ом 
GlobalUnlock(MyHandle);
// закрываем Clipboard
Clipboard.Close;
CRF.FormStyle:=fsStayOnTop;
end;

procedure Tmyps.FormDestroy(Sender: TObject);
begin
tmr1.Enabled:=False;
end;

procedure Tmyps.cbb1Click(Sender: TObject);
begin
cbb1.Text:='';
tmr1.Enabled:=False;
end;

procedure Tmyps.chk1Click(Sender: TObject);
begin
  if chk1.Checked then begin
  // снимаем блокировку области памяти занятую Clipboard-ом
     GlobalUnlock(MyHandle);
  // закрываем Clipboard
     Clipboard.Close;
  if FileExists(ExtractFilePath(ParamStr(0))+'mypass.ini.Rij') then begin
     s:=ExtractFilePath(ParamStr(0))+ExtractOnlyFileName(ExtractFilePath(ParamStr(0))+'mypass.ini.Rij');
     DecryptFile(ExtractFilePath(ParamStr(0))+'mypass.ini.Rij',s,KeyRelease);
     edt.mmo1.Lines.LoadFromFile(s);
     for i:=0 to edt.mmo1.Lines.Count-1 do begin
     s:=edt.mmo1.Lines.Strings[i];
     if s = '[PASS]' then edt.mmo1.Lines.Delete(i);
     end;
     edt.ShowModal;
  if FileExists(ExtractFilePath(ParamStr(0))+'mypass.ini') then begin
     cbb1.Items.LoadFromFile(ExtractFilePath(ParamStr(0))+'mypass.ini');
  for i:=0 to cbb1.Items.Count-1 do begin
     s:=cbb1.Items.Strings[i];
  if s = '[PASS]' then cbb1.Items.Delete(i);
     login.Text:=s3;
     sayt.Text:=s1;
     ps.Text:=s4;
  end;
   EncryptFile(ExtractFilePath(ParamStr(0))+'mypass.ini',ExtractFilePath(ParamStr(0))+'mypass.ini.Rij',KeyRelease);
   DeleteFile(ExtractFilePath(ParamStr(0))+'mypass.ini');
  end;
  end;
   CRF.chk3.Checked:=True;
  end else begin
  if FileExists(ExtractFilePath(ParamStr(0))+'mypass.ini') then begin
     EncryptFile(ExtractFilePath(ParamStr(0))+'mypass.ini',ExtractFilePath(ParamStr(0))+'mypass.ini.Rij',KeyRelease);
     DeleteFile(ExtractFilePath(ParamStr(0))+'mypass.ini');
  end;
  end;
end;

procedure Tmyps.chk2Click(Sender: TObject);
begin
  if chk2.Checked then begin
     // снимаем блокировку области памяти занятую Clipboard-ом
     GlobalUnlock(MyHandle);
     // закрываем Clipboard
     Clipboard.Close;
  end;
end;

end.
