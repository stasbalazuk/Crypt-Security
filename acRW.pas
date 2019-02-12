unit acRW;

interface

uses
  Classes,  SysUtils;

procedure AppendStringToFile (FileName :String; S :String);
// дописывает строку s (в смысле Delphi) к файлу FileName

function AppendedStringFromFile (FileName :String) :String;
// Возвращает строку дописаную к файлу FileName процедурой AppendStringToFile

implementation
const
  MySignature = '@TXT:';

// Структура файла с нашей допиской:
//   1  <исходный файл>
//   2  <сигнатура наличия нашей дописки>
//   3  <дописка>
//   4  <позиция в файле с которой начинается наша сигнатура (4 байта - Longword)>

procedure AppendStringToFile (FileName :String; S :String);
// дописывает строку s (в смысле Delphi) к файлу FileName
var
  MySignaturePosition :Longword;
  MySignatureBuf      :String;
begin
  with  TFileStream.Create(FileName,fmOpenReadWrite)  do try // открытие потока на чтение и запись
    try
      // Проверка наличия нашей сигнатуры
      // спозиционируемся на 4-й элемент нашей структуры, и прочитаем его
      if  Size < SizeOf(MySignaturePosition)  then
        Abort;  // в файле нет необходимого числа байт, т.е. файл не имеет нашей дописки
      Seek(-SizeOf(MySignaturePosition),soFromEnd);
      ReadBuffer(MySignaturePosition,SizeOf(MySignaturePosition));
      if  MySignaturePosition+Longword(Length(MySignature))+SizeOf(MySignaturePosition) > Size  then
        Abort;  // позиция сигнатуры за пределами файла, т.е. файл не имеет нашей дописки
      // спозиционируемся на предполагаемую сигнатуру
      Position := MySignaturePosition;
      // прочитаем сигнатуру в MySignatureBuf
      // поскольку String - это Longstring, то сначала надо обеспечить необходимый размер MySignatureBuf:
      SetLength(MySignatureBuf,Length(MySignature));
      ReadBuffer(MySignatureBuf[1],Length(MySignature));
      // теперь проверим что прочитанный фрагмент файла действительно является сигнатурой
      if  MySignatureBuf <> MySignature  then
        Abort;  // прочитанный фрагмент не сигнатура, т.е. файл не имеет нашей дописки
      // теперь мы точно знаем что файл имеет нашу сигнатуру
    except on eAbort  do begin
      // файл не имеет нашей дописки, значит надо сначала записать сигнатуру
      MySignaturePosition := Size;     // позиция сигнатуры в файле
      Position := MySignaturePosition;
      WriteBuffer(MySignature[1],Length(MySignature));  // запись сигнатуры
      // теперь файл имеет нашу сигнатуру
      end;
    end;
    // поток спозиционирован сразу за сигнатурой, т.е. можно писать дописку и в
    // MySignaturePosition позиция сигнатуры которую надо будет записать после
    // дописки.
    // запишем s
    WriteBuffer(s[1],Length(s));
    // запишем MySignaturePosition
    WriteBuffer(MySignaturePosition,SizeOf(MySignaturePosition));
    // установим новый размер файла
    Size := Position;
    // все
  finally
    Free;  // закрытие потока
  end;
end;

function AppendedStringFromFile (FileName :String) :String;
// Возвращает строку дописаную к файлу FileName процедурой AppendStringToFile
var
  MySignaturePosition :Longword;
  MySignatureBuf      :String;
begin
  with  TFileStream.Create(FileName,fmOpenRead)  do try // открытие потока на чтение
    try
      // Проверка наличия нашей сигнатуры
      // спозиционируемся на 4-й элемент нашей структуры, и прочитаем его
      if  Size < SizeOf(MySignaturePosition)  then
        Abort;  // в файле нет необходимого числа байт, т.е. файл не имеет нашей дописки
      Seek(-SizeOf(MySignaturePosition),soFromEnd);
      ReadBuffer(MySignaturePosition,SizeOf(MySignaturePosition));
      if  MySignaturePosition+Longword(Length(MySignature))+SizeOf(MySignaturePosition) > Size  then
        Abort;  // позиция сигнатуры за пределами файла, т.е. файл не имеет нашей дописки
      // спозиционируемся на предполагаемую сигнатуру
      Position := MySignaturePosition;
      // прочитаем сигнатуру в MySignatureBuf
      // поскольку String - это Longstring, то сначала надо обеспечить ее необходимый размер:
      SetLength(MySignatureBuf,Length(MySignature));
      ReadBuffer(MySignatureBuf[1],Length(MySignature));
      // теперь проверим что прочитанный фрагмент файла действительно является сигнатурой
      if  MySignatureBuf <> MySignature  then
        Abort;  // прочитанный фрагмент не сигнатура, т.е. файл не имеет нашей дописки
      // теперь мы точно знаем что файл имеет нашу сигнатуру, поэтому можеи читать строку
      // причем ее размер равен Size-MySignaturePosition-Length(MySignature)-SizeOf(MySignaturePosition)
      // естественно читать надо в подготовленный буфер соответствующего размера (Longstring)
      SetLength(Result,Size-MySignaturePosition-Length(MySignature)-SizeOf(MySignaturePosition));
      if  Length(Result) > 0  then  // дописка не пустая строка
        ReadBuffer(Result[1],Length(Result));
      // все.
    except on eAbort  do
      // файл не имеет нашей дописки, значит просто вернем пустую строку
      Result := '';
    end;
  finally
    Free;  // закрытие потока
  end;
end;

end.
