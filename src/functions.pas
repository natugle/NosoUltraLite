unit functions;

{$mode objfpc}{$H+}

{ NosoUltraLite v 0.1a. (Alfa Test Version)

  Made in 2022 by P Bjørn Biermann Madsen

  NosoUltraLite is based on code made by NosoCoin Project.

  This is free and unencumbered software released into the public domain.

  Anyone is free to copy, modify, publish, use, compile, sell, or
  distribute this software, either in source code form or as a compiled
  binary, for any purpose, commercial or non-commercial, and by any
  means.

  In jurisdictions that recognize copyright laws, the author or authors
  of this software dedicate any and all copyright interest in the
  software to the public domain. We make this dedication for the benefit
  of the public at large and to the detriment of our heirs and
  successors. We intend this dedication to be an overt act of
  relinquishment in perpetuity of all present and future rights to this
  software under copyright law.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
  OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
  OTHER DEALINGS IN THE SOFTWARE.

  For more information, please refer to <http://unlicense.org/>
  }

interface

uses
  Classes, SysUtils,  DateUtils, strutils, Base64,
  ClpSignerUtilities, HlpHashFactory,
  nl_signerUtils;

const
Feeconst = 10000;
MinimunFee = 10;
Protocol = 1;
ProgramVersion = '0.1';

HexAlphabet : string = '0123456789ABCDEF';
B58Alphabet : string = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
B36Alphabet : string = '0123456789abcdefghijklmnopqrstuvwxyz';

Type
DivResult = packed record
   cociente : string[255];
   residuo : string[255];
   end;



function GetUTMTimeStamp(): string;
function GetFee(amount: int64): int64;
function B64toHex(B64: String): String;
function GetProtoHeader(OrdType, TimeStamp, TrxType: String): string;
function GetOrderHash(TextLine:string):String;
function GetTransferHash(TextLine:string):String;
function GetStringSigned(StringtoSign, PrivateKey:String):String;

function Int2Curr(Value: int64): string;
function HashSha256String(StringToHash:string):string;
function HashMD160String(StringToHash:string):String;
function IsValidAddress(Address:String):boolean;
function IsValid58(base58text:string):boolean;
function IsValidReference(Ref:String):boolean;

function ClearLeadingCeros(numero:string):string;
function BMAdicion(numero1,numero2:string):string;
Function PonerCeros(numero:String;cuantos:integer):string;
Function BMMultiplicar(Numero1,Numero2:string):string;
Function BMDividir(Numero1,Numero2:string):DivResult;
Function BMExponente(Numero1,Numero2:string):string;
function BMHexToDec(numerohex:string):string;
function BMHexTo58(numerohex:string;alphabetnumber:integer):string;
function BMB58resumen(numero58:string):string;
function BMDecTo58(numero:string):string;

function ByteToString(const Value: TBytes): String;
function StrToByte(const Value: String): TBytes;

implementation

function GetUTMTimeStamp(): string;
begin
  result := IntToStr(DateTimeToUnix(Now, false));
end;

// Returns the GUI representation of any ammount of coins
function Int2Curr(Value: int64): string;
begin
Result := IntTostr(Abs(Value));
result :=  AddChar('0',Result, 9);
Insert('.',Result, Length(Result)-7);
if Value <0 then Result := '-'+Result;
end;

function GetFee(amount: int64): int64;
begin
  result := amount div FeeConst;
  if result < MinimunFee then result := MinimunFee;
end;

function B64toHex(B64: String): String;
var
  data, str :String;
  i :Integer;
begin
  result := '';
  str := '';
  data := DecodeStringBase64(B64);
  for i := 1 to Length(data) do str :=  str + IntToHex(Byte(data[i]),2);
  result := str;
end;

function GetProtoHeader(OrdType, TimeStamp, TrxType: String): string;
begin
  result := 'NSL'+OrdType+' '+IntToStr(protocol)+' '+ProgramVersion+' '+TimeStamp+' '+
  OrdType+' 1 $'+TrxType;
end;

// Returns a order hash
function GetOrderHash(TextLine:string):String;
Begin
  Result := HashSha256String(TextLine);
  Result := 'OR'+BMHexTo58(Result,36);
End;

// Returns a transfer hash
function GetTransferHash(TextLine:string):String;
var
  hash: string = '';
  sum: string = '';
  chk: string = '';
Begin
  hash := HashSha256String(TextLine);
  hash := BMHexTo58(hash,58);
  sum := BMB58resumen(hash);
  chk := BMDecTo58(sum);
  Result := 'tR'+hash+chk;
End;

// Returns the signature of a specified string
function GetStringSigned(StringtoSign, PrivateKey:String):String;
var
  Signature, MessageAsBytes: TBytes;
  sign: string;
Begin
MessageAsBytes :=StrToByte(DecodeStringBase64(StringtoSign));
Signature := TSignerUtils.SignMessage(MessageAsBytes, StrToByte(DecodeStringBase64(PrivateKey)),
      TKeyType.SECP256K1);
Result := EncodeStringBase64(ByteToString(Signature));
End;

function ByteToString(const Value: TBytes): String;
var
  I: integer;
  S : String;
  Letra: char;
begin
S := '';
for I := Length(Value)-1 Downto 0 do
   begin
   letra := Chr(Value[I]);
   S := letra + S;
   end;
Result := S;
end;

function StrToByte(const Value: String): TBytes;
var
  I: integer;
begin
SetLength(Result, Length(Value));
   for I := 0 to Length(Value) - 1 do
      Result[I] := ord(Value[I + 1]);
end;

// Returns the SHA256 of a estring
function HashSha256String(StringToHash:string):string;
Begin
result :=
THashFactory.TCrypto.CreateSHA2_256().ComputeString(StringToHash, TEncoding.UTF8).ToString();
End;

// Returns hash MD160 of a string
function HashMD160String(StringToHash:string):String;
Begin
result :=
THashFactory.TCrypto.CreateRIPEMD160().ComputeString(StringToHash, TEncoding.UTF8).ToString();
End;

// Checks if a string is a valid address
function IsValidAddress(Address:String):boolean;
var
  OrigHash : String;
  Clave:String;
Begin
result := false;
trim(address);
if ((length(address)>20) and (address[1] = 'N') ) then
   begin
   OrigHash := Copy(Address,2,length(address)-3);
   if IsValid58(OrigHash) then
      begin
      Clave := BMDecTo58(BMB58resumen(OrigHash));
      OrigHash := 'N'+OrigHash+clave;
      if OrigHash = Address then result := true else result := false;
      end;
   end
End;

// Checks if a string is a valid address
function IsValidReference(Ref:String):boolean;
var
  i: integer;
begin
  result := false;
  if length(Ref) > 0 then
    for i := 1 to length(Ref) do if not (Ref[i] in ['0'..'9','A'..'Z', 'a'..'z','_','-']) then  Exit;
  result := true;
end;

// Returns if a string is a valid Base58
function IsValid58(base58text:string):boolean;
var
  counter : integer;
Begin
result := true;
if length(base58text) > 0 then
   begin
   for counter := 1 to length(base58text) do
      begin
      if pos (base58text[counter],B58Alphabet) = 0 then
         begin
         result := false;
         break;
         end;
      end;
   end
else result := false;
End;

// ***************************FUNCTIONS OF BIGMATHS*****************************
// REMOVES LEFT CEROS
function ClearLeadingCeros(numero:string):string;
var
  count : integer = 0;
  movepos : integer = 0;
Begin
result := '';
if numero[1] = '-' then movepos := 1;
for count := 1+movepos to length(numero) do
   begin
   if numero[count] <> '0' then result := result + numero[count];
   if ((numero[count]='0') and (length(result)>0)) then result := result + numero[count];
   end;
if result = '' then result := '0';
if ((movepos=1) and (result <>'0')) then result := '-'+result;
End;

// ADDS 2 NUMBERS
function BMAdicion(numero1,numero2:string):string;
var
  longitude : integer = 0;
  count: integer = 0;
  carry : integer = 0;
  resultado : string = '';
  thiscol : integer;
  ceros : integer;
Begin
longitude := length(numero1);
if length(numero2)>longitude then
   begin
   longitude := length(numero2);
   ceros := length(numero2)-length(numero1);
   while count < ceros do
      begin
      numero1 := '0'+numero1;
      count := count+1;
      end;
   end
else
   begin
   ceros := length(numero1)-length(numero2);
      while count < ceros do
      begin
      numero2 := '0'+numero2;
      count := count+1;
      end;
   end;
for count := longitude downto 1 do
   Begin
   thiscol := StrToInt(numero1[count]) + StrToInt(numero2[count])+carry;
   carry := 0;
   if thiscol > 9 then
      begin
      thiscol := thiscol-10;
      carry := 1;
      end;
   resultado := inttoStr(thiscol)+resultado;
   end;
if carry > 0 then resultado := '1'+resultado;
result := resultado;
End;

// DRAW CEROS FOR MULTIPLICATION
Function PonerCeros(numero:String;cuantos:integer):string;
var
  contador : integer = 0;
  NewNumber : string;
Begin
NewNumber := numero;
while contador < cuantos do
   begin
   NewNumber := NewNumber+'0';
   contador := contador+1;
   end;
result := NewNumber;
End;

// MULTIPLIER
Function BMMultiplicar(Numero1,Numero2:string):string;
var
  count,count2 : integer;
  sumandos : array of string;
  thiscol : integer;
  carry: integer = 0;
  cantidaddeceros : integer = 0;
  TotalSuma : string = '0';
Begin
setlength(sumandos,length(numero2));
for count := length(numero2) downto 1 do
   begin
   for count2 := length(numero1) downto 1 do
      begin
      thiscol := (StrToInt(numero2[count]) * StrToInt(numero1[count2])+carry);
      carry := thiscol div 10;
      ThisCol := ThisCol - (carry*10);
      sumandos[cantidaddeceros] := IntToStr(thiscol)+ sumandos[cantidaddeceros];
      end;
   if carry > 0 then sumandos[cantidaddeceros] := IntToStr(carry)+sumandos[cantidaddeceros];
   carry := 0;
   sumandos[cantidaddeceros] := PonerCeros(sumandos[cantidaddeceros],cantidaddeceros);
   cantidaddeceros := cantidaddeceros+1;
   end;
for count := 0 to length(sumandos)-1 do
   TotalSuma := BMAdicion(Sumandos[count],totalsuma);
result := ClearLeadingCeros(TotalSuma);
End;

// DIVIDES TO NUMBERS
Function BMDividir(Numero1,Numero2:string):DivResult;
var
  counter : integer;
  cociente : string = '';
  long : integer;
  Divisor : Int64;
  ThisStep : String = '';
Begin
long := length(numero1);
Divisor := StrToInt64(numero2);
for counter := 1 to long do
   begin
   ThisStep := ThisStep + Numero1[counter];
   if StrToInt(ThisStep) >= Divisor then
      begin
      cociente := cociente+IntToStr(StrToInt(ThisStep) div Divisor);
      ThisStep := (IntToStr(StrToInt(ThisStep) mod Divisor));
      end
   else cociente := cociente+'0';
   end;
result.cociente := ClearLeadingCeros(cociente);
result.residuo := ClearLeadingCeros(thisstep);
End;

// CALCULATES A EXPONENTIAL NUMBER
Function BMExponente(Numero1,Numero2:string):string;
var
  count : integer = 0;
  resultado : string = '';
Begin
if numero2 = '1' then result := numero1
else if numero2 = '0' then result := '1'
else
   begin
   resultado := numero1;
   for count := 2 to StrToInt(numero2) do
      resultado := BMMultiplicar(resultado,numero1);
   result := resultado;
   end;
End;

// HEX TO DECIMAL
function BMHexToDec(numerohex:string):string;
var
  DecValues : array of integer;
  ExpValues : array of string;
  MultipliValues : array of string;
  counter : integer;
  Long : integer;
  Resultado : string = '0';
Begin
Long := length(numerohex);
numerohex := uppercase(numerohex);
setlength(DecValues,0);
setlength(ExpValues,0);
setlength(MultipliValues,0);
setlength(DecValues,Long);
setlength(ExpValues,Long);
setlength(MultipliValues,Long);
for counter := 1 to Long do
   DecValues[counter-1] := Pos(NumeroHex[counter],HexAlphabet)-1;
for counter := 1 to long do
   ExpValues[counter-1] := BMExponente('16',IntToStr(long-counter));
for counter := 1 to Long do
   MultipliValues[counter-1] := BMMultiplicar(ExpValues[counter-1],IntToStr(DecValues[counter-1]));
for counter := 1 to long do
   Resultado := BMAdicion(resultado,MultipliValues[counter-1]);
result := resultado;
End;

// Hex a base 58
function BMHexTo58(numerohex:string;alphabetnumber:integer):string;
var
  decimalvalue : string;
  restante : integer;
  ResultadoDiv : DivResult;
  Resultado : string = '';
  AlpahbetUsed : String;
Begin
AlpahbetUsed := B58Alphabet;
if alphabetnumber=36 then AlpahbetUsed := B36Alphabet;
decimalvalue := BMHexToDec(numerohex);
while length(decimalvalue) >= 2 do
   begin
   ResultadoDiv := BMDividir(decimalvalue,IntToStr(alphabetnumber));
   DecimalValue := Resultadodiv.cociente;
   restante := StrToInt(ResultadoDiv.residuo);
   resultado := AlpahbetUsed[restante+1]+resultado;
   end;
if StrToInt(decimalValue) >= alphabetnumber then
   begin
   ResultadoDiv := BMDividir(decimalvalue,IntToStr(alphabetnumber));
   DecimalValue := Resultadodiv.cociente;
   restante := StrToInt(ResultadoDiv.residuo);
   resultado := AlpahbetUsed[restante+1]+resultado;
   end;
if StrToInt(decimalvalue) > 0 then resultado := AlpahbetUsed[StrToInt(decimalvalue)+1]+resultado;
result := resultado;
End;

// RETURN THE SUMATORY OF A BASE58
function BMB58resumen(numero58:string):string;
var
  counter, total : integer;
Begin
total := 0;
for counter := 1 to length(numero58) do
   begin
   total := total+Pos(numero58[counter],B58Alphabet)-1;
   end;
result := IntToStr(total);
End;

// CONVERTS A DECIMAL VALUE TO A BASE58 STRING
function BMDecTo58(numero:string):string;
var
  decimalvalue : string;
  restante : integer;
  ResultadoDiv : DivResult;
  Resultado : string = '';
Begin
decimalvalue := numero;
while length(decimalvalue) >= 2 do
   begin
   ResultadoDiv := BMDividir(decimalvalue,'58');
   DecimalValue := Resultadodiv.cociente;
   restante := StrToInt(ResultadoDiv.residuo);
   resultado := B58Alphabet[restante+1]+resultado;
   end;
if StrToInt(decimalValue) >= 58 then
   begin
   ResultadoDiv := BMDividir(decimalvalue,'58');
   DecimalValue := Resultadodiv.cociente;
   restante := StrToInt(ResultadoDiv.residuo);
   resultado := B58Alphabet[restante+1]+resultado;
   end;
if StrToInt(decimalvalue) > 0 then resultado := B58Alphabet[StrToInt(decimalvalue)+1]+resultado;
result := resultado;
end;

end.
