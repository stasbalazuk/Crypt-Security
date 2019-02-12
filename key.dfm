object keys: Tkeys
  Left = 593
  Top = 308
  BorderIcons = [biMinimize]
  BorderStyle = bsDialog
  Caption = #1042#1074#1086#1076' '#1082#1083#1102#1095#1072
  ClientHeight = 36
  ClientWidth = 296
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  Position = poMainFormCenter
  OnActivate = FormActivate
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object EdtCertValidToS1: TEdit
    Left = 8
    Top = 8
    Width = 185
    Height = 21
    ImeName = #1056#1091#1089#1089#1082#1072#1103
    TabOrder = 0
    OnKeyPress = EdtCertValidToS1KeyPress
  end
  object btn1: TButton
    Left = 200
    Top = 8
    Width = 89
    Height = 21
    Caption = '-= '#1055#1088#1086#1074#1077#1088#1080#1090#1100' =-'
    TabOrder = 1
    OnClick = btn1Click
  end
  object DCP_sha5121: TDCP_sha512
    Id = 30
    Algorithm = 'SHA512'
    HashSize = 512
    Left = 48
    Top = 8
  end
  object DCP_rijndael1: TDCP_rijndael
    Id = 9
    Algorithm = 'Rijndael'
    MaxKeySize = 256
    BlockSize = 128
    Left = 16
    Top = 8
  end
  object tmr1: TTimer
    OnTimer = tmr1Timer
    Left = 96
    Top = 8
  end
end
