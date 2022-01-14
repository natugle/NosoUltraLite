unit umain;

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
  Classes, SysUtils, FileUtil, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ComCtrls, DateUtils,
  opensslsockets, fphttpclient, lNetComponents, lNet, Functions;

const
Feeconst = 10000;
MinimunFee = 10;
Protocol = 1;
ProgramVersion = '0.1';
NodeIP = '192.210.226.118';
NodePort = 8080;

Type

WalletData = Packed Record
   Hash : String[40];              // Public hash
   Custom : String[40];            // Custom alias
   PublicKey : String[255];        // Public key
   PrivateKey : String[255];       // Private key
   Balance : int64;                // Last known balance
   Pending : int64;                // Last pending balance
   Score : int64;                  // Aditional field
   LastOP : int64;                 // last operation block
   end;

var
  FILE_Wallet : File of WalletData; // Wallet file pointer


type

  { TfmMain }

  TfmMain = class(TForm)
    btBalance: TButton;
    btSend: TButton;
    btPending: TButton;
    btImportKeysButton2: TButton;
    btLastBlock: TButton;
    edAmount: TEdit;
    edAddress: TEdit;
    edPubKey: TEdit;
    edMessage: TEdit;
    edReceiver: TEdit;
    lbBalance: TLabel;
    lbBal: TLabel;
    lbAddress: TLabel;
    lbPublicKey: TLabel;
    lbAmount: TLabel;
    lbMessage: TLabel;
    lbReceiver: TLabel;
    mmLog: TMemo;
    OpenDialog1: TOpenDialog;
    PageControl1: TPageControl;
    StatusBar1: TStatusBar;
    tsSettings: TTabSheet;
    tsWallet: TTabSheet;
    procedure btBalanceClick(Sender: TObject);
    procedure btImportKeysButton2Click(Sender: TObject);
    procedure btLastBlockClick(Sender: TObject);
    procedure btSendClick(Sender: TObject);
    procedure btPendingClick(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    { private declarations }
    FormActivated: Boolean;
    FPrivateKey, FPublicKey, FAddress, FResponse: string;
    FBalance: int64;
    KeyFilename: string;
    FNet: TLConnection;
    LTCP: TLTCPComponent;
    CanSend: boolean;
    procedure OnErr(const msg: string; aSocket: TLSocket);
    procedure OnRec(aSocket: TLSocket);
    procedure OnCon(aSocket: TLSocket);
    procedure OnDis(aSocket: TLSocket);
    procedure SendFunds();
    procedure LoadKeys();
    function FPHTTPSimpleGet(URL: string): string;
    function GetBalance(adrs: string):int64;
    function GetLastBlock():integer;
    function GetPending():boolean;
    Procedure SendTransaction(trx: string);
  public
    { public declarations }
    procedure Log(str: string);
  end;

var
  fmMain: TfmMain;

implementation

{$R *.lfm}

{ TfmMain }
procedure TfmMain.Log(str: string);
begin
  while mmLog.Lines.Count > 100 do mmLog.Lines.Delete(0);
  mmLog.Lines.Add(str);
  mmLog.SelStart := Length(mmLog.Lines.Text);
end;

procedure Tfmmain.SendFunds();
var
  adr, ref, tim, head, errmsg, tid, oid, sig: string;
  amnt, com: int64;
  amount, fee: string;
begin
 adr := ''; ref := ''; errmsg := ''; amnt := -1; com := 10;

 if IsValidAddress(Trim(edReceiver.text)) then adr := Trim(edReceiver.text)
 else errmsg := 'Invalid address! ';
 amnt := StrToInt64Def(StringReplace(edAmount.Text,'.','',[rfReplaceAll, rfIgnoreCase]),-1);
 if amnt < 1 then errmsg := errmsg + 'Invalid amount ! '
 else com := GetFee(amnt);
 if getbalance(FAddress) < amnt + com then errmsg := errmsg + 'Not enough fund ! ';

 if Trim(edMessage.Text) = '' then ref := 'nul'
   else if IsValidReference(Trim(edMessage.Text)) then ref := Trim(edMessage.Text)
     else errmsg := errmsg + 'Invalid message ! ';
 if errmsg <> '' then
 begin
   Log(errmsg);
   exit;
 end;
 amount := inttostr(amnt);
 fee := inttostr(com);
 tim := GetUTMTimeStamp();
 head := GetProtoHeader('ORDER', tim, 'TRFR');
 tid := GetTransferHash(tim+FAddress+adr+amount+IntTostr(getlastblock()));
 oid := GetOrderHash('1'+tim+tid);
 sig := GetStringSigned(tim+FAddress+adr+amount+fee+'1', FPrivateKey);

 SendTransaction(head +' '+ Oid + ' 1 TRFR ' + tim +' '+ ref + ' 1 ' +FPublicKey +' '+ FAddress +' '+
 adr +' '+ fee +' '+ amount +' '+ sig +' '+ tid);
 end;
(*
NSLORDER 1 1.0 1640259468 ORDER 1 $TRFR OR4pm367bseixiuh63611z5qyu64qir2b3xmap47p10l1oq457z0 1 TRFR 1640259468 test-test 1 BCbW2zVfGsnnkm+5L07y6XgZA5HNLuxXbwZRkGPaZrEB7Z/uZ0MRV8/dA68vS3opX7eI8msTJQOdqt1Gr8jF/GM= N3REqszDpRYmUwvyXRJWYXjQr6eiZH5 N2EGVCGj1dm7hrH41bbadMpjZWMShDG 10 1 MEYCIQDTvaex3obqV9k18iP8pMIMV1zkZ0Qelln7LXVSR7zfSQIhAPNEOZWaXHkPvcEqHqFfichy4VzpKxzyKeZM6/aKozZk tR24C9LdNpZ7BmL1MYRdiQ2doCju5z5bELqEJPiftaUcz9Lg
*)

// Sets the global variables of keys and address
procedure TfmMain.LoadKeys();
var
  WalletFile : file of WalletData;
  data : WalletData;
begin
//
  if fileexists(KeyFilename) then
  begin
    AssignFile(WalletFile,KeyFilename);
    try
      Reset(WalletFile);
      seek(walletfile,0);
      read(walletfile,data);
      closeFile(WalletFile);
      FPrivateKey := data.PrivateKey;
      FPublicKey := data.PublicKey;
      FAddress := data.Hash;
    except on E:Exception do
    begin
      ShowMessage('Can not load file: ' + KeyFilename);
    end;
    end;
  end
  else ShowMessage('Can not load file: ' + KeyFilename);
end;

function TfmMain.FPHTTPSimpleGet(URL: string): string;
begin
  Result := '';
  With TFPHttpClient.Create(Nil) do
  try
    try
      Result := Get(URL);
    except
      on E: Exception do
        Result := 'Error: ' + E.Message;
    end;
  finally
    Free;
  end;
end;

// sets the global variable FBalance and return the balance as integer
function TfmMain.GetBalance(adrs: string):int64;
var
  r: string;
  i, j: integer;
begin
  result := -1;
  r := FPHTTPSimpleGet('https://explorer.nosocoin.com/api/v1/address/'+adrs+'.json');
  i := Pos('balance', r);
  j := Pos('incoming', r);
  if i > 0 then r := Copy(r, i+9, j - (i+11));
  FBalance := StrToInt64Def(StringReplace(r,'.','',[rfReplaceAll, rfIgnoreCase]),-1);
  result := FBalance;
end;

function TfmMain.GetLastBlock():integer;
var
  i: integer = 0;
  s: string = '';
begin
  result := -1;
  FResponse := '';
  CanSend := false;
  LTCP.Connect(NodeIP, NodePort);
  while not CanSend do Application.ProcessMessages;
  LTCP.SendMessage('NODESTATUS'+#13#10);
  while FResponse = '' do Application.ProcessMessages;
  i := Pos('NODESTATUS', FResponse);
  if i > 0 then
  begin
    s := trim(copy(FResponse,14,6));
    result := strtointdef(s, -1);
  end;
end;

function TfmMain.GetPending():boolean;
begin
  CanSend := false;
  LTCP.Connect(NodeIP, NodePort);
  while not CanSend do Application.ProcessMessages;
  LTCP.SendMessage('NSLPEND'+#13#10);
  while FResponse = '' do Application.ProcessMessages;
  //* Fixme: block for new transactions while there is a pending transaction or change balance check
  result := false;
end;

Procedure TfmMain.SendTransaction(trx: string);
begin
  CanSend := false;
  LTCP.Connect(NodeIP, NodePort);
  while not CanSend do Application.ProcessMessages;
  LTCP.SendMessage(trx+#13#10);
  Log(trx);
end;

procedure TfmMain.btBalanceClick(Sender: TObject);
begin
  Log(IntToStr(GetBalance(FAddress)));
end;

procedure TfmMain.btImportKeysButton2Click(Sender: TObject);
var
  ok: boolean = false;
begin
  If Not DirectoryExists('data') then
    If Not CreateDir ('data') Then
      ShowMessage('Failed to create "data" directory !')
    else
      ShowMessage('Created "data" directory');

  if FileExists(KeyFilename) then
    if MessageDlg('Import Keys', 'Your keys will be replaced'+#13+'Do you wish to Execute ?', mtConfirmation,
       [mbYes, mbNo],0) = mrYes
      then ok := true;

  if (not FileExists(KeyFilename)) or ok then
  begin
    ok := false;
    OpenDialog1.InitialDir := ExtractFileDir(Application.Exename);
    OpenDialog1.Filter := 'Noso wallet file *.pkw|*.pkw';
    if OpenDialog1.Execute then
    begin
      if fileExists(OpenDialog1.Filename) then ok := CopyFile(OpenDialog1.Filename,KeyFilename)
        else ShowMessage('No keys loaded');
    end
    else ShowMessage('No keys loaded');
 end;
 if ok then MessageDlg('File '+OpenDialog1.FileName+' successfully copied to '+
      KeyFilename,mtInformation,[mbOk],0)
 else MessageDlg('Copying failed',mtWarning,[mbOk],0);
 if ok then LoadKeys();
end;

procedure TfmMain.btLastBlockClick(Sender: TObject);
begin
  Log(IntToStr(GetLastBlock()));
end;

procedure TfmMain.btSendClick(Sender: TObject);
begin
  SendFunds();
end;

procedure TfmMain.btPendingClick(Sender: TObject);
var
  Str, r  :String;
  a: int64;
begin
  GetPending();
end;


procedure TfmMain.FormCreate(Sender: TObject);
begin
  //
  LTCP := TLTCPComponent.Create(nil);
  LTCP.Port := 0;
  LTCP.OnReceive := @OnRec;
  LTCP.OnError := @OnErr;
  LTCP.OnDisconnect := @OnDis;
  LTCP.OnConnect := @OnCon;
  LTCP.Timeout := 5000;
  LTCP.ReuseAddress := True;
  FNet := LTCP;
end;

procedure TfmMain.FormDestroy(Sender: TObject);
begin
  //
  FreeAndNil(FNet);
  FreeAndNil(LTCP);
end;

procedure TfmMain.FormShow(Sender: TObject);
begin
  if FormActivated then Exit
  else FormActivated := true;

  KeyFilename := 'data/wallet.pkw';
  if FileExists(KeyFilename) then loadkeys()
  else btImportKeysButton2Click(self);

  edAddress.Text := FAddress;
  edPubKey.Text := FPublicKey;
  if FAddress <> '' then lbBalance.Caption := Int2Curr(GetBalance(FAddress)); //* get balance from API (or summary ?)
end;

procedure TfmMain.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  CloseAction := caFree;
  if FNet.Connected then begin
    CloseAction := caNone; // make sure we quit gracefuly
    FNet.Disconnect; // call disconnect (soft)
  end;
end;

procedure TfmMain.OnCon(aSocket: TLSocket);
begin
  CanSend := true;
  Log('Connected to remote host');
end;

procedure TfmMain.OnErr(const msg: string; aSocket: TLSocket);
begin
  Log(msg);
end;

procedure TfmMain.OnRec(aSocket: TLSocket);
var
  s: string;
begin
  if aSocket.GetMessage(s) > 0 then begin
    Log(s);
//* handle response
    if FResponse = '' then FResponse := s;
  end;
end;

procedure TfmMain.OnDis
(aSocket: TLSocket);
begin
  Log('Connection lost');
  CanSend := False;
end;

end.
