unit GetUrlBrowser;

interface

function GetURL(Browser: string): string;

implementation

uses DdeMan,SysUtils;

function GetURL(Browser: string): string;
var
 Client_DDE: TDDEClientConv;
 temp: PAnsiChar;
begin
 Result := '';
 Client_DDE:= TDDEClientConv.Create( nil );
 with Client_DDE do
  begin
   SetLink(Browser, 'WWW_GetWindowInfo');
   temp := RequestData('0xFFFFFFFF');
   Result := StrPas(temp);
  // Return only the URL part
   Delete(Result, Pos(',', Result), Length(Result)-Pos(',', Result)+1);
   // Remove quotes
   Delete(Result, 1, 1);
   Delete(Result, Length(Result), 1);
   // ************
   StrDispose(temp);
   CloseLink;
  end;
 Client_DDE.Free;
end;

end.
